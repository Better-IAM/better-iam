import { randomInt } from 'node:crypto';
import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { grantDeadline } from '../grant-deadline.js';
import type { ProtocolMount } from '../options.js';
import { SdJwtError } from '../sd-jwt.js';
import { hash, id } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  activeIssuerKey,
  assertVc,
  createIssuerKey,
  createNonce,
  holderFromProof,
  issueCredential,
  issuerJwks,
  issuerKeys,
  issuerUrl,
  matchesHash,
  mayRequest,
  offerIdOf,
  offerToken,
  statusListToken,
  sweepCredentials,
  typeByName,
  vcClaims,
  vcOptions,
  verifyLocalPresentation,
  writeStatus,
  type ResolvedVcOptions,
  type VcCredentialStatus,
  type VcCredentialType,
  type VcIssuedCredential,
  type VcIssuerKey,
  type VcOffer,
  type VcStatusList,
  type VcSweepResult,
  type VerifiedCredential,
} from '../vc.js';

export interface VcCredentialTypeInput {
  tenantId: string;
  name: string;
  displayName: string;
  description?: string;
  /** The credential type identifier; default `{issuer}/types/{name}`. */
  vct?: string;
  claims: unknown[];
  lifetimeMs?: number;
  requireMfa?: boolean;
  enabled?: boolean;
  backgroundColor?: string;
  textColor?: string;
}
export interface VcCredentialTypeUpdate {
  tenantId: string;
  name: string;
  displayName?: string;
  description?: string | null;
  claims?: unknown[];
  lifetimeMs?: number;
  requireMfa?: boolean;
  enabled?: boolean;
  backgroundColor?: string | null;
  textColor?: string | null;
}
export interface VcCredentialTypeView {
  id: string;
  tenantId: string;
  name: string;
  displayName: string;
  description?: string;
  vct: string;
  claims: VcCredentialType['claims'];
  lifetimeMs: number;
  requireMfa: boolean;
  enabled: boolean;
  backgroundColor?: string;
  textColor?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}
export interface VcIssuedView {
  id: string;
  tenantId: string;
  typeName: string;
  vct: string;
  identityId: string;
  holderThumbprint: string;
  keyId: string;
  statusListId: string;
  statusIndex: number;
  status: VcCredentialStatus;
  /** `expired` once past `validUntil`, whatever the status. */
  state: VcCredentialStatus | 'expired';
  claimNames: string[];
  via: VcIssuedCredential['via'];
  issuedBy: string;
  issuedAt: number;
  validUntil: number;
  revokedAt?: number;
  revokedBy?: string;
  reason?: string;
}
export interface VcIssuerKeyView {
  id: string;
  kid: string;
  status: VcIssuerKey['status'];
  alg: 'ES256';
  publicJwk: VcIssuerKey['publicJwk'];
  createdAt: number;
  rotatedAt?: number;
  retiredAt?: number;
}
/** What a wallet scans: the OpenID4VCI credential offer and its `openid-credential-offer://` link. */
export interface VcOfferResult {
  offerId: string;
  credentialOffer: {
    credential_issuer: string;
    credential_configuration_ids: string[];
    grants: Record<string, Record<string, unknown>>;
  };
  offerUri: string;
  /** The one-time PIN the wallet asks for, when the offer requires one: give it to the person another way. */
  txCode?: string;
  expiresAt: number;
}
export type VcVerification =
  | ({ valid: true } & VerifiedCredential)
  | { valid: false; reason: string; message: string };

const typeNamePattern = /^[a-z][a-z0-9_-]{0,63}$/;
const colorPattern = /^#[0-9a-fA-F]{6}$/;
const PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

function typeView(type: VcCredentialType): VcCredentialTypeView {
  const { uniqueKey: _key, ...view } = type;
  return view as VcCredentialTypeView;
}
function issuedView(record: VcIssuedCredential, now: number): VcIssuedView {
  const { uniqueKey: _key, expiresAt: _expires, ...view } = record;
  return { ...(view as Omit<VcIssuedView, 'state'>), state: record.validUntil <= now ? 'expired' : record.status };
}
function keyView(key: VcIssuerKey): VcIssuerKeyView {
  return {
    id: key.id,
    kid: key.kid,
    status: key.status,
    alg: key.alg,
    publicJwk: key.publicJwk,
    createdAt: key.createdAt,
    ...(key.rotatedAt !== undefined ? { rotatedAt: key.rotatedAt } : {}),
    ...(key.retiredAt !== undefined ? { retiredAt: key.retiredAt } : {}),
  };
}
const typeName = (value: unknown) => {
  if (typeof value !== 'string' || !typeNamePattern.test(value))
    throw new IamError('INVALID_INPUT', 'Type names use 1-64 lowercase letters, digits, "_" or "-"');
  return value;
};
const color = (value: unknown, name: string) => {
  if (typeof value !== 'string' || !colorPattern.test(value))
    throw new IamError('INVALID_INPUT', `${name} must be a #rrggbb color`);
  return value;
};

/**
 * The `verifiableCredentials` API group: credential types (`iam:vc:manage`), issued credentials and their status
 * (`iam:vc:read`, `iam:vc:revoke`), wallet offers for others (`iam:vc:issue`), and, for members, credentials and
 * offers for themselves where policies allow `vc:request` on `credential-type/{name}`. `nonce`, `verify` and
 * `issuerMetadata` are public.
 */
export function createVerifiableCredentialsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const tenantOf = (value: unknown) => text(value, 'tenantId');

  async function scopedType(tx: IamStore, tenantId: string, name: unknown): Promise<VcCredentialType> {
    const type = await typeByName(tx, tenantId, typeName(name));
    if (!type) throw new IamError('NOT_FOUND', 'Unknown credential type', 404);
    return type;
  }

  /** Checks for people getting a credential for themselves: not "view as", MFA when the type asks, then policy. */
  async function selfServiceRefusal(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    type: VcCredentialType,
  ): Promise<IamError | undefined> {
    if (principal.session.impersonatorId)
      return new IamError('IMPERSONATION_RESTRICTED', 'Credentials cannot be issued while viewing as someone', 403);
    // An agent acting for a person never binds that person's credential to a key of its own choosing.
    if (principal.session.kind === 'delegated')
      return new IamError('ACCESS_DENIED', 'Agents acting for people cannot obtain credentials for them', 403);
    if (principal.identity.tenantId !== tenant.id)
      return new IamError('ACCESS_DENIED', 'Credentials are issued to members of this organization', 403);
    if (type.requireMfa && principal.identity.kind === 'user' && !principal.session.mfa)
      return new IamError('MFA_REQUIRED', 'Sign in with multi-factor authentication to get this credential', 403);
    if (!type.enabled) return new IamError('TYPE_DISABLED', 'This credential type is disabled', 409);
    if (!(await mayRequest(ctx, tx, principal, tenant, type)))
      return new IamError('ACCESS_DENIED', 'Access denied', 403);
    return undefined;
  }

  /**
   * The latest a self-service credential may stay valid: assumed roles and temporary credentials end with their
   * session; standing sign-ins with the time-limited grants (just-in-time, expiring bindings or memberships, access
   * windows) that allow `vc:request`.
   */
  async function requestDeadline(tx: IamStore, principal: AuthenticatedPrincipal, tenantId: string): Promise<number> {
    const kind = principal.session.kind;
    if (kind !== 'user' && kind !== 'api-key') return principal.session.expiresAt;
    return grantDeadline(ctx, tx, principal, tenantId, Infinity, 'vc:request');
  }

  /** A self-service call in its own transaction; a refusal is audited (committed) before it is thrown. */
  async function selfService<T>(
    credential: CredentialInput,
    tenantId: string,
    name: string,
    run: (tx: IamStore, principal: AuthenticatedPrincipal, tenant: Tenant, type: VcCredentialType) => Promise<T>,
  ): Promise<T> {
    const authenticated = await ctx.principals.authenticate(credential);
    const outcome = await ctx.store.transaction(async (tx): Promise<{ error: IamError } | { value: T }> => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      const tenant = await ctx.tenant(tx, tenantId);
      const type = await scopedType(tx, tenantId, name);
      const refusal = await selfServiceRefusal(tx, principal, tenant, type);
      if (refusal) {
        await ctx.events.audit(tx, principal, 'vc:request', tenantId, `credential-type/${type.name}`, 'deny', false, {
          reason: refusal.code,
        });
        return { error: refusal };
      }
      return { value: await run(tx, principal, tenant, type) };
    });
    if ('error' in outcome) throw outcome.error;
    return outcome.value;
  }

  async function makeOffer(
    tx: IamStore,
    tenant: Tenant,
    type: VcCredentialType,
    identity: Identity,
    principal: AuthenticatedPrincipal,
    options: ResolvedVcOptions,
    selfService: boolean,
    withTxCode: boolean,
  ): Promise<VcOfferResult> {
    const offerId = id();
    const code = offerToken('biam_vco', offerId);
    const txCode = withTxCode ? String(randomInt(1_000_000)).padStart(6, '0') : undefined;
    const now = ctx.now();
    const offer = await tx.insert<VcOffer>('vcOffers', {
      id: offerId,
      tenantId: tenant.id,
      typeId: type.id,
      identityId: identity.id,
      codeHash: hash(code),
      ...(txCode ? { txCodeHash: hash(`${offerId}:${txCode}`) } : {}),
      txCodeAttempts: 0,
      selfService,
      mfa: principal.session.mfa,
      createdAt: now,
      createdBy: principal.identity.id,
      expiresAt: now + options.offerLifetimeMs,
    });
    await ctx.events.audit(tx, principal, 'vc:offer:create', tenant.id, `vc/offers/${offer.id}`, 'allow', false, {
      type: type.name,
      identityId: identity.id,
      txCode: Boolean(txCode),
    });
    const credentialOffer = {
      credential_issuer: issuerUrl(ctx, tenant.id),
      credential_configuration_ids: [type.name],
      grants: {
        [PRE_AUTHORIZED]: {
          'pre-authorized_code': code,
          ...(txCode
            ? { tx_code: { length: 6, input_mode: 'numeric', description: 'The PIN shown with the offer' } }
            : {}),
        },
      },
    };
    return {
      offerId: offer.id,
      credentialOffer,
      offerUri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`,
      ...(txCode ? { txCode } : {}),
      expiresAt: offer.expiresAt,
    };
  }

  async function changeStatus(
    tx: IamStore,
    record: VcIssuedCredential,
    next: VcCredentialStatus,
    actorId: string,
    reason?: string,
  ): Promise<VcIssuedCredential> {
    const allowed =
      (next === 'revoked' && record.status !== 'revoked') ||
      (next === 'suspended' && record.status === 'valid') ||
      (next === 'valid' && record.status === 'suspended');
    if (!allowed)
      throw new IamError('INVALID_TRANSITION', `A ${record.status} credential cannot become ${next}`, 409);
    await writeStatus(ctx, tx, record, next);
    const now = ctx.now();
    const changed: VcIssuedCredential = { ...record, status: next };
    if (next === 'revoked') Object.assign(changed, { revokedAt: now, revokedBy: actorId });
    if (reason !== undefined) changed.reason = text(reason, 'reason', 512);
    return tx.put<VcIssuedCredential>('vcIssued', changed);
  }

  return {
    /** Issuer keys, credential types, issued credentials by state, and status lists. Requires iam:vc:read. */
    status: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:read', 'vc/issuer', async ({ tx, tenant }) => {
        assertVc(ctx);
        const now = ctx.now();
        const issued = await tx.find<VcIssuedCredential>('vcIssued', { tenantId: tenant.id });
        const live = issued.filter((record) => record.validUntil > now);
        return {
          issuer: issuerUrl(ctx, tenant.id),
          metadataUrl: `${ctx.config.baseURL.origin}/.well-known/openid-credential-issuer${ctx.config.basePath}/vc/${tenant.id}`,
          keys: (await issuerKeys(tx, tenant.id)).filter((key) => key.status !== 'retired').map(keyView),
          types: (await tx.find<VcCredentialType>('vcCredentialTypes', { tenantId: tenant.id })).length,
          credentials: {
            valid: live.filter((record) => record.status === 'valid').length,
            suspended: live.filter((record) => record.status === 'suspended').length,
            revoked: live.filter((record) => record.status === 'revoked').length,
            expired: issued.length - live.length,
          },
          statusLists: (await tx.find<VcStatusList>('vcStatusLists', { tenantId: tenant.id })).length,
        };
      }),

    /** Defines a credential type: its claims, lifetime and wallet display. Requires iam:vc:manage. */
    createType: (credential: CredentialInput, input: VcCredentialTypeInput) => {
      const name = typeName(input.name);
      return operation(credential, tenantOf(input.tenantId), 'iam:vc:manage', `vc/types/${name}`, async ({ tx, tenant, principal }) => {
        const options = assertVc(ctx);
        if (await typeByName(tx, tenant.id, name))
          throw new IamError('CONFLICT', 'A credential type with this name exists', 409);
        const own = issuerUrl(ctx, tenant.id);
        const vct = input.vct === undefined ? `${own}/types/${name}` : text(input.vct, 'vct', 256);
        if (/\s/.test(vct)) throw new IamError('INVALID_INPUT', 'vct cannot contain whitespace');
        // Type identifiers under this deployment's issuers belong to the issuer they name.
        if (vct.startsWith(`${ctx.config.baseURL.origin}${ctx.config.basePath}/vc/`) && !vct.startsWith(`${own}/`))
          throw new IamError('INVALID_INPUT', "vct names another organization's issuer");
        const now = ctx.now();
        const type = await tx.insert<VcCredentialType>('vcCredentialTypes', {
          id: id(),
          tenantId: tenant.id,
          uniqueKey: name,
          name,
          displayName: text(input.displayName, 'displayName', 128),
          ...(input.description !== undefined ? { description: text(input.description, 'description', 512) } : {}),
          vct,
          claims: vcClaims(input.claims, ctx.catalog.identityAttributes),
          lifetimeMs:
            input.lifetimeMs === undefined
              ? Math.min(30 * 86_400_000, options.maxLifetimeMs)
              : integer(input.lifetimeMs, 'lifetimeMs', 5 * 60_000, options.maxLifetimeMs),
          requireMfa: input.requireMfa === true,
          enabled: input.enabled !== false,
          ...(input.backgroundColor !== undefined ? { backgroundColor: color(input.backgroundColor, 'backgroundColor') } : {}),
          ...(input.textColor !== undefined ? { textColor: color(input.textColor, 'textColor') } : {}),
          createdAt: now,
          createdBy: principal.identity.id,
          updatedAt: now,
        });
        // The first type also creates the tenant's issuer key.
        await activeIssuerKey(ctx, tx, tenant.id, principal.identity.id);
        return typeView(type);
      });
    },

    /** Changes a type's display, claims, lifetime or switches; its name and vct stay. Requires iam:vc:manage. */
    updateType: (credential: CredentialInput, input: VcCredentialTypeUpdate) => {
      const name = typeName(input.name);
      return operation(credential, tenantOf(input.tenantId), 'iam:vc:manage', `vc/types/${name}`, async ({ tx, tenant }) => {
        const options = assertVc(ctx);
        const type = await scopedType(tx, tenant.id, name);
        const next: VcCredentialType = { ...type, updatedAt: ctx.now() };
        if (input.displayName !== undefined) next.displayName = text(input.displayName, 'displayName', 128);
        if (input.description === null) delete next.description;
        else if (input.description !== undefined) next.description = text(input.description, 'description', 512);
        if (input.claims !== undefined) next.claims = vcClaims(input.claims, ctx.catalog.identityAttributes);
        if (input.lifetimeMs !== undefined)
          next.lifetimeMs = integer(input.lifetimeMs, 'lifetimeMs', 5 * 60_000, options.maxLifetimeMs);
        for (const key of ['requireMfa', 'enabled'] as const)
          if (input[key] !== undefined) {
            if (typeof input[key] !== 'boolean') throw new IamError('INVALID_INPUT', `${key} must be a boolean`);
            next[key] = input[key];
          }
        for (const key of ['backgroundColor', 'textColor'] as const)
          if (input[key] === null) delete next[key];
          else if (input[key] !== undefined) next[key] = color(input[key], key);
        return typeView(await tx.put<VcCredentialType>('vcCredentialTypes', next));
      });
    },

    /** Deletes a type; refused while valid credentials of it exist (disable it, or revoke them first). Requires iam:vc:manage. */
    deleteType: (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = typeName(input.name);
      return operation(credential, tenantOf(input.tenantId), 'iam:vc:manage', `vc/types/${name}`, async ({ tx, tenant }) => {
        assertVc(ctx);
        const type = await scopedType(tx, tenant.id, name);
        const now = ctx.now();
        const live = (await tx.find<VcIssuedCredential>('vcIssued', { tenantId: tenant.id, typeId: type.id })).filter(
          (record) => record.status !== 'revoked' && record.validUntil > now,
        );
        if (live.length)
          throw new IamError('RESOURCE_IN_USE', `${live.length} credentials of this type are still valid`, 409);
        for (const offer of await tx.find<VcOffer>('vcOffers', { tenantId: tenant.id, typeId: type.id }))
          await tx.delete('vcOffers', offer.id);
        await tx.delete('vcCredentialTypes', type.id);
        return { deleted: true };
      });
    },

    /** One credential type. Requires iam:vc:read. */
    getType: (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = typeName(input.name);
      return operation(credential, tenantOf(input.tenantId), 'iam:vc:read', `vc/types/${name}`, async ({ tx, tenant }) => {
        assertVc(ctx);
        return typeView(await scopedType(tx, tenant.id, name));
      });
    },

    /** Every credential type of the tenant, by name. Requires iam:vc:read. */
    listTypes: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:read', 'vc/types', async ({ tx, tenant }) => {
        assertVc(ctx);
        return (await tx.find<VcCredentialType>('vcCredentialTypes', { tenantId: tenant.id }))
          .sort((a, b) => (a.name < b.name ? -1 : 1))
          .map(typeView);
      }),

    /** The credential types the caller may request for themselves, with what each would disclose. No permission. */
    available: async (credential: CredentialInput, input: { tenantId: string }) => {
      assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        const result: VcCredentialTypeView[] = [];
        for (const type of await tx.find<VcCredentialType>('vcCredentialTypes', { tenantId, enabled: true }))
          if (!(await selfServiceRefusal(tx, principal, tenant, type))) result.push(typeView(type));
        return result.sort((a, b) => (a.name < b.name ? -1 : 1));
      });
    },

    /** A single-use nonce (`c_nonce`) for a holder proof, valid five minutes. Public. */
    nonce: async (input: { tenantId: string }) => {
      assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      await ctx.tenant(ctx.store, tenantId);
      // Stateless (signed, checked and spent at use): handing nonces out writes nothing.
      return { nonce: createNonce(ctx, tenantId), expiresIn: 300 };
    },

    /**
     * Issues a credential of `type` for the caller, bound to the key in `proof` (an OpenID4VCI proof JWT over a nonce
     * from `nonce`). Needs `vc:request` on `credential-type/{type}` (and MFA when the type asks). Audited as
     * `vc:credential:issue`; a refusal as a denied `vc:request`.
     */
    request: (credential: CredentialInput, input: { tenantId: string; type: string; proof: string }) =>
      selfService(credential, tenantOf(input.tenantId), input.type, async (tx, principal, tenant, type) => {
        const holder = await holderFromProof(ctx, tx, tenant.id, input.proof);
        const issued = await issueCredential(ctx, tx, {
          tenant,
          type,
          identity: principal.identity,
          holderJwk: holder.jwk,
          holderThumbprint: holder.thumbprint,
          via: 'request',
          actor: principal,
          issuedBy: principal.identity.id,
          selfService: true,
          mfa: principal.session.mfa,
          deadline: await requestDeadline(tx, principal, tenant.id),
        });
        return { credential: issued.credential, record: issuedView(issued.record, ctx.now()) };
      }),

    /**
     * An OpenID4VCI credential offer (pre-authorized code) a wallet redeems: for the caller (`vc:request`) or, with
     * `identityId`, for someone else (`iam:vc:issue`). `txCode: true` adds a 6-digit PIN the wallet asks for.
     */
    createOffer: async (
      credential: CredentialInput,
      input: { tenantId: string; type: string; identityId?: string; txCode?: boolean },
    ): Promise<VcOfferResult> => {
      const options = assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      const withTxCode = input.txCode === true;
      if (input.identityId === undefined || input.identityId === authenticated.identity.id)
        return selfService(credential, tenantId, input.type, (tx, principal, tenant, type) =>
          makeOffer(tx, tenant, type, principal.identity, principal, options, true, withTxCode),
        );
      const name = typeName(input.type);
      return operation(credential, tenantId, 'iam:vc:issue', `vc/types/${name}`, async ({ tx, tenant, principal }) => {
        const type = await scopedType(tx, tenant.id, name);
        if (!type.enabled) throw new IamError('TYPE_DISABLED', 'This credential type is disabled', 409);
        const identity = await ctx.activeIdentity(tx, text(input.identityId, 'identityId'), tenant.id);
        if (identity.status !== 'active' || ctx.identityExpired(identity))
          throw new IamError('IDENTITY_INACTIVE', 'Credentials are issued to active members only', 409);
        return makeOffer(tx, tenant, type, identity, principal, options, false, withTxCode);
      });
    },

    /** The caller's own credentials in the tenant, newest first. */
    mine: async (credential: CredentialInput, input: { tenantId: string }) => {
      assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.kind === 'delegated') throw new IamError('ACCESS_DENIED', 'Access denied', 403);
        const now = ctx.now();
        return (await tx.find<VcIssuedCredential>('vcIssued', { tenantId, identityId: principal.identity.id }))
          .sort((a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1))
          .slice(0, 100)
          .map((record) => issuedView(record, now));
      });
    },

    /** Issued credentials, newest first, by type, identity or state. Requires iam:vc:read. */
    listIssued: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type?: string;
        identityId?: string;
        state?: VcIssuedView['state'];
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:read', 'vc/credentials', async ({ tx, tenant }) => {
        assertVc(ctx);
        const limit = integer(input.limit ?? 100, 'limit', 1, 500);
        const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
        const filter: Record<string, unknown> = { tenantId: tenant.id };
        if (input.type !== undefined) filter.typeName = typeName(input.type);
        if (input.identityId !== undefined) filter.identityId = text(input.identityId, 'identityId');
        const now = ctx.now();
        const views = (await tx.find<VcIssuedCredential>('vcIssued', filter))
          .map((record) => issuedView(record, now))
          .filter((view) => input.state === undefined || view.state === input.state)
          .sort((a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1));
        return { credentials: views.slice(offset, offset + limit), total: views.length };
      }),

    /**
     * Revokes a credential for good (verifiers see it in the status list): the holder's own without permission,
     * anyone's with iam:vc:revoke.
     */
    revoke: async (credential: CredentialInput, input: { tenantId: string; credentialId: string; reason?: string }) => {
      assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      const credentialId = text(input.credentialId, 'credentialId');
      const authenticated = await ctx.principals.authenticate(credential);
      const found = await ctx.scoped<VcIssuedCredential>(ctx.store, 'vcIssued', credentialId, tenantId);
      // The holder's own path skips the permission, so only a session acting in its own unrestricted right takes it:
      // not "view as", not an agent acting for them, not a key or token narrowed by a session policy.
      if (
        found.identityId === authenticated.identity.id &&
        !authenticated.session.impersonatorId &&
        authenticated.session.kind !== 'delegated' &&
        !authenticated.session.policy &&
        !authenticated.session.sourcePolicy
      )
        return ctx.store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const record = await ctx.scoped<VcIssuedCredential>(tx, 'vcIssued', credentialId, tenantId);
          const changed = await changeStatus(tx, record, 'revoked', principal.identity.id, input.reason);
          await ctx.events.audit(tx, principal, 'vc:credential:revoke', tenantId, `vc/credentials/${credentialId}`, 'allow', false, {
            own: true,
          });
          return issuedView(changed, ctx.now());
        });
      return operation(credential, tenantId, 'iam:vc:revoke', `vc/credentials/${credentialId}`, async ({ tx, principal }) => {
        const record = await ctx.scoped<VcIssuedCredential>(tx, 'vcIssued', credentialId, tenantId);
        return issuedView(await changeStatus(tx, record, 'revoked', principal.identity.id, input.reason), ctx.now());
      });
    },

    /** Suspends a valid credential (reversible with `reinstate`). Requires iam:vc:revoke. */
    suspend: (credential: CredentialInput, input: { tenantId: string; credentialId: string; reason?: string }) =>
      operation(
        credential,
        tenantOf(input.tenantId),
        'iam:vc:revoke',
        `vc/credentials/${text(input.credentialId, 'credentialId')}`,
        async ({ tx, tenant, principal }) => {
          assertVc(ctx);
          const record = await ctx.scoped<VcIssuedCredential>(tx, 'vcIssued', input.credentialId, tenant.id);
          return issuedView(await changeStatus(tx, record, 'suspended', principal.identity.id, input.reason), ctx.now());
        },
      ),

    /** Lifts a suspension. Requires iam:vc:revoke. */
    reinstate: (credential: CredentialInput, input: { tenantId: string; credentialId: string }) =>
      operation(
        credential,
        tenantOf(input.tenantId),
        'iam:vc:revoke',
        `vc/credentials/${text(input.credentialId, 'credentialId')}`,
        async ({ tx, tenant, principal }) => {
          assertVc(ctx);
          const record = await ctx.scoped<VcIssuedCredential>(tx, 'vcIssued', input.credentialId, tenant.id);
          return issuedView(await changeStatus(tx, record, 'valid', principal.identity.id), ctx.now());
        },
      ),

    /** Issuer keys, oldest first (retired ones included). Requires iam:vc:read. */
    listKeys: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:read', 'vc/keys', async ({ tx, tenant }) => {
        assertVc(ctx);
        return (await issuerKeys(tx, tenant.id)).map(keyView);
      }),

    /**
     * A new signing key; the current one stays published as `previous`, so credentials it signed keep verifying.
     * Requires iam:vc:manage.
     */
    rotateKey: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:manage', 'vc/keys', async ({ tx, tenant, principal }) => {
        assertVc(ctx);
        const now = ctx.now();
        for (const key of await issuerKeys(tx, tenant.id))
          if (key.status === 'active')
            await tx.put<VcIssuerKey>('vcIssuerKeys', { ...key, status: 'previous', rotatedAt: now });
        return keyView(await createIssuerKey(ctx, tx, tenant.id, principal.identity.id));
      }),

    /**
     * Stops publishing a previous key: credentials it signed stop verifying. Refused while valid ones exist, unless
     * `force` (which revokes them). Requires iam:vc:manage.
     */
    retireKey: (credential: CredentialInput, input: { tenantId: string; kid: string; force?: boolean }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:vc:manage', 'vc/keys', async ({ tx, tenant, principal }) => {
        assertVc(ctx);
        const key = (await issuerKeys(tx, tenant.id)).find((item) => item.kid === input.kid);
        if (!key) throw new IamError('NOT_FOUND', 'Unknown issuer key', 404);
        if (key.status !== 'previous')
          throw new IamError('INVALID_TRANSITION', 'Only a previous key can be retired', 409);
        const now = ctx.now();
        const live = (await tx.find<VcIssuedCredential>('vcIssued', { tenantId: tenant.id, keyId: key.kid })).filter(
          (record) => record.status !== 'revoked' && record.validUntil > now,
        );
        if (live.length && input.force !== true)
          throw new IamError('RESOURCE_IN_USE', `${live.length} credentials signed by this key are still valid`, 409);
        for (const record of live) await changeStatus(tx, record, 'revoked', principal.identity.id, 'key-retired');
        return keyView(await tx.put<VcIssuerKey>('vcIssuerKeys', { ...key, status: 'retired', retiredAt: now }));
      }),

    /**
     * Verifies a presentation of a credential this deployment issued (signature, disclosures, key binding for
     * `audience` and `nonce`, current status). Public: returns `{ valid: false, reason }` instead of throwing.
     */
    verify: async (input: {
      presentation: string;
      audience?: string;
      nonce?: string;
      tenantId?: string;
    }): Promise<VcVerification> => {
      assertVc(ctx);
      try {
        const verified = await verifyLocalPresentation(ctx, text(input.presentation, 'presentation', 65536), {
          ...(input.audience !== undefined ? { audience: text(input.audience, 'audience', 512) } : {}),
          ...(input.nonce !== undefined ? { nonce: text(input.nonce, 'nonce', 256) } : {}),
          ...(input.tenantId !== undefined ? { tenantId: tenantOf(input.tenantId) } : {}),
        });
        return { valid: true, ...verified };
      } catch (error) {
        if (error instanceof SdJwtError) return { valid: false, reason: error.reason, message: error.message };
        throw error;
      }
    },

    /** The tenant's OpenID4VCI credential issuer metadata (also at /.well-known/openid-credential-issuer). Public. */
    issuerMetadata: async (input: { tenantId: string }) => {
      assertVc(ctx);
      const tenantId = tenantOf(input.tenantId);
      return issuerMetadata(ctx, ctx.store, await activeTenantOf(ctx, ctx.store, tenantId));
    },
  };
}

async function activeTenantOf(ctx: ServerContext, tx: IamStore, tenantId: string): Promise<Tenant> {
  const tenant = await ctx.tenant(tx, tenantId);
  if ((await ctx.ancestry(tx, tenant)).some((item) => item.status !== 'active'))
    throw new IamError('TENANT_INACTIVE', 'This organization is not active', 403);
  return tenant;
}

/** OpenID4VCI 1.0 credential issuer metadata for a tenant's enabled types. */
async function issuerMetadata(ctx: ServerContext, tx: IamStore, tenant: Tenant) {
  const issuer = issuerUrl(ctx, tenant.id);
  const types = (await tx.find<VcCredentialType>('vcCredentialTypes', { tenantId: tenant.id, enabled: true })).sort(
    (a, b) => (a.name < b.name ? -1 : 1),
  );
  return {
    credential_issuer: issuer,
    credential_endpoint: `${issuer}/credential`,
    nonce_endpoint: `${issuer}/nonce`,
    display: [{ name: tenant.name, locale: 'en' }],
    credential_configurations_supported: Object.fromEntries(
      types.map((type) => [
        type.name,
        {
          format: 'dc+sd-jwt',
          vct: type.vct,
          scope: type.name,
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256', 'ES384', 'EdDSA'] } },
          credential_metadata: {
            display: [
              {
                name: type.displayName,
                locale: 'en',
                ...(type.description ? { description: type.description } : {}),
                ...(type.backgroundColor ? { background_color: type.backgroundColor } : {}),
                ...(type.textColor ? { text_color: type.textColor } : {}),
              },
            ],
            claims: type.claims.map((claim) => ({
              path: [claim.name],
              ...(claim.label ? { display: [{ name: claim.label, locale: 'en' }] } : {}),
            })),
          },
        },
      ]),
    ),
  };
}

/** SD-JWT VC type metadata for `{issuer}/types/{name}`. */
function typeMetadata(type: VcCredentialType) {
  return {
    vct: type.vct,
    name: type.displayName,
    ...(type.description ? { description: type.description } : {}),
    display: [
      {
        locale: 'en',
        name: type.displayName,
        ...(type.description ? { description: type.description } : {}),
        ...(type.backgroundColor || type.textColor
          ? {
              rendering: {
                simple: {
                  ...(type.backgroundColor ? { background_color: type.backgroundColor } : {}),
                  ...(type.textColor ? { text_color: type.textColor } : {}),
                },
              },
            }
          : {}),
      },
    ],
    claims: type.claims.map((claim) => ({
      path: [claim.name],
      sd: claim.selective === false ? 'never' : 'always',
      ...(claim.label ? { display: [{ locale: 'en', label: claim.label }] } : {}),
    })),
  };
}

const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, dpop',
  'cache-control': 'no-store',
};
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  Response.json(body, { status, headers: { ...cors, ...headers } });
const oauthError = (status: number, error: string, description: string, headers: Record<string, string> = {}) =>
  json(status, { error, error_description: description }, headers);

/** Reads at most `limit` bytes of a body, stopping (and refusing) as soon as more arrive. */
async function bodyText(request: Request, limit: number): Promise<string> {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > limit) throw new IamError('PAYLOAD_TOO_LARGE', 'Request body too large', 413);
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      throw new IamError('PAYLOAD_TOO_LARGE', 'Request body too large', 413);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * The wallet-facing endpoints of every tenant's issuer, mounted beside the HTTP API (`{issuer}` is
 * `{origin}{basePath}/vc/{tenantId}`): `/.well-known/openid-credential-issuer{path}`, `/.well-known/jwt-vc-issuer{path}`
 * and `/.well-known/oauth-authorization-server{path}` metadata, `{issuer}/token` (pre-authorized code),
 * `{issuer}/nonce`, `{issuer}/credential`, `{issuer}/jwks.json`, `{issuer}/types/{name}` and
 * `{issuer}/status/{listId}` (Token Status List).
 */
export function createVcProtocol(ctx: ServerContext): ProtocolMount {
  const { basePath } = ctx.config;
  const prefix = `${basePath}/vc/`;
  const wellKnown = ['openid-credential-issuer', 'jwt-vc-issuer', 'oauth-authorization-server'] as const;
  const tenantPattern = /^[A-Za-z0-9_-]{1,128}$/;

  async function handle(request: Request): Promise<Response | undefined> {
    if (!vcOptions(ctx)) return undefined;
    const url = new URL(request.url);
    let tenantId: string | undefined;
    let rest = '';
    let metadata: (typeof wellKnown)[number] | undefined;
    for (const name of wellKnown) {
      const start = `/.well-known/${name}${prefix}`;
      if (url.pathname.startsWith(start)) {
        metadata = name;
        tenantId = url.pathname.slice(start.length);
      }
    }
    if (!metadata) {
      if (!url.pathname.startsWith(prefix)) return undefined;
      const path = url.pathname.slice(prefix.length);
      const slash = path.indexOf('/');
      tenantId = slash < 0 ? path : path.slice(0, slash);
      rest = slash < 0 ? '' : path.slice(slash + 1);
    }
    if (!tenantId || !tenantPattern.test(tenantId)) return json(404, { error: 'not_found' });
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      if (request.method === 'GET') return await read(tenantId, metadata, rest);
      if (request.method === 'POST') {
        if (rest === 'token') return await tokenEndpoint(request, tenantId);
        if (rest === 'nonce') {
          await activeTenantOf(ctx, ctx.store, tenantId);
          return json(200, { c_nonce: createNonce(ctx, tenantId) });
        }
        if (rest === 'credential') return await credentialEndpoint(request, tenantId);
      }
      return json(404, { error: 'not_found' });
    } catch (error) {
      if (error instanceof IamError)
        return json(error.status, { error: error.status === 404 ? 'not_found' : 'invalid_request', error_description: error.message });
      return json(500, { error: 'server_error' });
    }
  }

  async function read(
    tenantId: string,
    metadata: (typeof wellKnown)[number] | undefined,
    rest: string,
  ): Promise<Response> {
    // Public reads stay off the write lock: nothing here creates or changes a row.
    const reader = ctx.store;
    const tenant = await activeTenantOf(ctx, reader, tenantId);
    const issuer = issuerUrl(ctx, tenantId);
    if (metadata === 'openid-credential-issuer') return json(200, await issuerMetadata(ctx, reader, tenant));
    if (metadata === 'jwt-vc-issuer') return json(200, { issuer, jwks: await issuerJwks(reader, tenantId) });
    if (metadata === 'oauth-authorization-server')
      return json(200, {
        issuer,
        token_endpoint: `${issuer}/token`,
        grant_types_supported: [PRE_AUTHORIZED],
        'pre-authorized_grant_anonymous_access_supported': true,
      });
    if (rest === 'jwks.json') return json(200, await issuerJwks(reader, tenantId));
    if (rest.startsWith('types/')) {
      const type = await typeByName(reader, tenantId, rest.slice('types/'.length));
      return type ? json(200, typeMetadata(type)) : json(404, { error: 'not_found' });
    }
    if (rest.startsWith('status/')) {
      const list = await reader.get<VcStatusList>('vcStatusLists', rest.slice('status/'.length));
      if (!list || list.tenantId !== tenantId) return json(404, { error: 'not_found' });
      return new Response(await statusListToken(ctx, reader, list), {
        status: 200,
        headers: {
          ...cors,
          'content-type': 'application/statuslist+jwt',
          'cache-control': `public, max-age=${assertVc(ctx).statusListTtlSeconds}`,
        },
      });
    }
    return json(404, { error: 'not_found' });
  }

  /** Pre-authorized code grant: one offer, one access token, the PIN checked at most five times. */
  async function tokenEndpoint(request: Request, tenantId: string): Promise<Response> {
    if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/x-www-form-urlencoded'))
      return oauthError(400, 'invalid_request', 'Send a form-encoded token request');
    const form = new URLSearchParams(await bodyText(request, 8192));
    if (form.get('grant_type') !== PRE_AUTHORIZED)
      return oauthError(400, 'unsupported_grant_type', 'Only the pre-authorized code grant is supported');
    const code = form.get('pre-authorized_code') ?? '';
    const offerId = offerIdOf(code, 'biam_vco');
    const outcome = await ctx.store.transaction(async (tx): Promise<Response> => {
      await activeTenantOf(ctx, tx, tenantId);
      const offer = offerId ? await tx.get<VcOffer>('vcOffers', offerId) : undefined;
      const now = ctx.now();
      if (
        !offer ||
        offer.tenantId !== tenantId ||
        !matchesHash(offer.codeHash, code) ||
        offer.redeemedAt !== undefined ||
        offer.expiresAt <= now
      )
        return oauthError(400, 'invalid_grant', 'The offer is unknown, used or expired');
      if (offer.txCodeHash) {
        const txCode = form.get('tx_code');
        // A wallet that did not ask for the PIN yet has not guessed wrong.
        if (!txCode) return oauthError(400, 'invalid_request', 'This offer needs its PIN (tx_code)');
        if (!matchesHash(offer.txCodeHash, `${offer.id}:${txCode}`)) {
          const attempts = offer.txCodeAttempts + 1;
          // Five wrong PINs end the offer.
          await tx.put<VcOffer>('vcOffers', {
            ...offer,
            txCodeAttempts: attempts,
            ...(attempts >= 5 ? { expiresAt: now } : {}),
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: offer.identityId,
            action: 'vc:offer:redeem',
            resourceId: `vc/offers/${offer.id}`,
            outcome: 'deny',
            timestamp: now,
            metadata: { reason: attempts >= 5 ? 'pin-locked' : 'wrong-pin', attempts },
          });
          return oauthError(400, 'invalid_grant', attempts >= 5 ? 'Too many wrong PINs; the offer ended' : 'The PIN is wrong');
        }
      }
      const accessToken = offerToken('biam_vcat', offer.id);
      const accessExpiresAt = now + 5 * 60_000;
      await tx.put<VcOffer>('vcOffers', {
        ...offer,
        redeemedAt: now,
        accessTokenHash: hash(accessToken),
        accessExpiresAt,
        expiresAt: accessExpiresAt,
      });
      return json(200, { access_token: accessToken, token_type: 'Bearer', expires_in: 300 });
    });
    return outcome;
  }

  /** Issues the offered credential to the wallet that holds the access token, bound to the key its proof names. */
  async function credentialEndpoint(request: Request, tenantId: string): Promise<Response> {
    const authorization = request.headers.get('authorization') ?? '';
    const accessToken = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
    const offerId = offerIdOf(accessToken, 'biam_vcat');
    const challenge = { 'www-authenticate': 'Bearer error="invalid_token"' };
    if (!offerId) return oauthError(401, 'invalid_token', 'A bearer access token is required', challenge);
    let body: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(await bodyText(request, 16384));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('shape');
      body = parsed as Record<string, unknown>;
    } catch {
      return oauthError(400, 'invalid_credential_request', 'Send a JSON credential request');
    }
    return ctx.store.transaction(async (tx): Promise<Response> => {
      const tenant = await activeTenantOf(ctx, tx, tenantId);
      const offer = await tx.get<VcOffer>('vcOffers', offerId);
      const now = ctx.now();
      if (
        !offer ||
        offer.tenantId !== tenantId ||
        !matchesHash(offer.accessTokenHash, accessToken) ||
        (offer.accessExpiresAt ?? 0) <= now ||
        offer.credentialId !== undefined
      )
        return oauthError(401, 'invalid_token', 'The access token is unknown, used or expired', challenge);
      const type = await tx.get<VcCredentialType>('vcCredentialTypes', offer.typeId);
      if (!type || type.tenantId !== tenantId)
        return oauthError(400, 'unknown_credential_configuration', 'The offered credential type no longer exists');
      /** A refused redemption is answered, and audited: the transaction commits either way. */
      const refuse = async (status: number, error: string, description: string, reason: string) => {
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: offer.identityId,
          action: 'vc:offer:redeem',
          resourceId: `vc/offers/${offer.id}`,
          outcome: 'deny',
          timestamp: now,
          metadata: { reason, type: type.name },
        });
        return oauthError(status, error, description);
      };
      const requested = body.credential_configuration_id ?? (body.vct === type.vct ? type.name : undefined);
      if (requested !== type.name)
        return oauthError(400, 'unknown_credential_configuration', 'This token is for another credential');
      const proofs = body.proofs as { jwt?: unknown } | undefined;
      const proof =
        Array.isArray(proofs?.jwt) && proofs.jwt.length === 1
          ? proofs.jwt[0]
          : (body.proof as { proof_type?: unknown; jwt?: unknown } | undefined)?.proof_type === 'jwt'
            ? (body.proof as { jwt?: unknown }).jwt
            : undefined;
      if (proof === undefined) return oauthError(400, 'invalid_proof', 'Send one jwt proof');
      const identity = await tx.get<Identity>('identities', offer.identityId);
      if (!identity || identity.tenantId !== tenantId || identity.status !== 'active' || ctx.identityExpired(identity))
        return refuse(400, 'invalid_credential_request', 'The holder is no longer a member', 'identity-inactive');
      // Self-service offers are re-decided now: access or MFA may have changed since the offer was made, and the
      // credential ends with the time-limited grants that allow it.
      let deadline: number | undefined;
      if (offer.selfService) {
        const principal = ctx.decisions.simulatedPrincipal(identity, offer.mfa);
        if ((type.requireMfa && identity.kind === 'user' && !offer.mfa) || !(await mayRequest(ctx, tx, principal, tenant, type)))
          return refuse(403, 'access_denied', 'The holder may no longer receive this credential', 'access-changed');
        deadline = await grantDeadline(ctx, tx, principal, tenantId, Infinity, 'vc:request');
      }
      let holder: { jwk: import('jose').JWK; thumbprint: string };
      try {
        holder = await holderFromProof(ctx, tx, tenantId, proof);
      } catch (error) {
        const code = (error as IamError).code === 'INVALID_NONCE' ? 'invalid_nonce' : 'invalid_proof';
        return oauthError(400, code, (error as Error).message);
      }
      let issued: Awaited<ReturnType<typeof issueCredential>>;
      try {
        issued = await issueCredential(ctx, tx, {
          tenant,
          type,
          identity,
          holderJwk: holder.jwk,
          holderThumbprint: holder.thumbprint,
          via: 'offer',
          actor: { actorId: identity.id },
          // An administrator's offer is theirs to answer for; a self-service one is the person's.
          issuedBy: offer.selfService ? identity.id : offer.createdBy,
          selfService: offer.selfService,
          mfa: offer.mfa,
          offerId: offer.id,
          ...(deadline !== undefined ? { deadline } : {}),
        });
      } catch (error) {
        if (error instanceof IamError)
          return refuse(400, 'invalid_credential_request', error.message, error.code.toLowerCase());
        throw error;
      }
      const { accessTokenHash: _token, ...rest } = offer;
      await tx.put<VcOffer>('vcOffers', { ...rest, credentialId: issued.record.id });
      // OpenID4VCI 1.0 answers `credentials`; `credential` keeps wallets on the earlier drafts working.
      return json(200, { credentials: [{ credential: issued.credential }], credential: issued.credential });
    });
  }

  return { handle };
}

/** `iam.verifiableCredentials`: server-side verification and the scheduler job, no credential. */
export function createVcRuntime(ctx: ServerContext) {
  return {
    /** Whether the `verifiableCredentials` option is on. */
    get enabled() {
      return vcOptions(ctx) !== undefined;
    },
    /** Verifies a presentation of a credential this deployment issued; throws `SdJwtError` with the reason. */
    verify: (
      presentation: string,
      options: { audience?: string; nonce?: string; tenantId?: string; requireKeyBinding?: boolean } = {},
    ) => verifyLocalPresentation(ctx, presentation, options),
    /** Revokes credentials of people who are no longer active members (run hourly). */
    sweep: (input?: { tenantId?: string }): Promise<VcSweepResult> => sweepCredentials(ctx, input),
    /** A holder-proof nonce for a tenant, for applications embedding their own wallet flow. */
    nonce: (tenantId: string) => createNonce(ctx, tenantId),
    /** The tenant's issuer identifier. */
    issuer: (tenantId: string) => issuerUrl(ctx, tenantId),
  };
}

