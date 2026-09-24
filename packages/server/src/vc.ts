import {
  createHash,
  createHmac,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  randomInt,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';
import { decryptSecret, encryptSecret } from '@better-iam/auth';
import {
  IamError,
  type AuthenticatedPrincipal,
  type IamPlugin,
  type IamStore,
  type Identity,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { calculateJwkThumbprint, exportJWK, type JWK } from 'jose';
import type { ServerContext } from './context.js';
import { departmentOf } from './departments.js';
import type { ResolvedResource } from './options.js';
import {
  SD_JWT_VC_TYPE,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  SdJwtError,
  issueSdJwt,
  reservedVcClaims,
  setStatusAt,
  signStatusList,
  statusAt,
  verifyHolderProof,
  verifySdJwt,
  type VerifiedSdJwt,
} from './sd-jwt.js';
import { teamsOf } from './teams.js';
import { hash, id, sameHash, token } from './utils.js';

/**
 * Verifiable credentials: each tenant is an issuer of SD-JWT VCs (IETF SD-JWT-based Verifiable Credentials) that
 * wallets hold and present, with selective disclosure, holder key binding, and revocation through a Token Status List.
 * Credential types map identity data (email, name, attributes, teams, department, static values) to claims. People get
 * credentials for themselves when policies allow `vc:request` on `credential-type/{name}`, through the API or a
 * wallet (OpenID4VCI pre-authorized code flow, served by the protocol mount below); administrators issue them for
 * others (`iam:vc:issue`). Verifiers check presentations offline with the issuer's keys and status list, or through
 * `iam.verifiableCredentials.verify`.
 */

export interface VerifiableCredentialOptions {
  /** The longest credential lifetime any type may set, in milliseconds (default 365 days, 5 minutes to 5 years). */
  maxLifetimeMs?: number;
  /** Entries per status list (default 65536; 1024 to 1048576, a multiple of 1024). A list is used up to half full. */
  statusListSize?: number;
  /** How long a wallet offer can be redeemed (default 10 minutes, 1 minute to 24 hours). */
  offerLifetimeMs?: number;
  /** How long a status list token is valid (default 24 hours) and how long verifiers may cache it (`ttl`, 5 minutes). */
  statusListLifetimeMs?: number;
  statusListTtlSeconds?: number;
  /** How long credential records stay after the credential expired (default 30 days, 1 to 3650). */
  recordRetentionDays?: number;
}

export interface ResolvedVcOptions {
  maxLifetimeMs: number;
  statusListSize: number;
  offerLifetimeMs: number;
  statusListLifetimeMs: number;
  statusListTtlSeconds: number;
  recordRetentionMs: number;
}

const MINUTE = 60_000;
const DAY = 86_400_000;

function bounded(value: unknown, fallback: number, min: number, max: number, name: string) {
  const resolved = value ?? fallback;
  if (typeof resolved !== 'number' || !Number.isSafeInteger(resolved) || resolved < min || resolved > max)
    throw new IamError(
      'INVALID_CONFIG',
      `verifiableCredentials.${name} must be an integer between ${min} and ${max}`,
    );
  return resolved;
}

export function resolveVcOptions(value: unknown): ResolvedVcOptions | undefined {
  if (value === undefined || value === false) return undefined;
  if (value !== true && (typeof value !== 'object' || value === null || Array.isArray(value)))
    throw new IamError('INVALID_CONFIG', 'verifiableCredentials must be true or an options object');
  const options = (value === true ? {} : value) as VerifiableCredentialOptions;
  const size = bounded(options.statusListSize, 65536, 1024, 1_048_576, 'statusListSize');
  if (size % 1024) throw new IamError('INVALID_CONFIG', 'verifiableCredentials.statusListSize must be a multiple of 1024');
  return {
    maxLifetimeMs: bounded(options.maxLifetimeMs, 365 * DAY, 5 * MINUTE, 5 * 365 * DAY, 'maxLifetimeMs'),
    statusListSize: size,
    offerLifetimeMs: bounded(options.offerLifetimeMs, 10 * MINUTE, MINUTE, DAY, 'offerLifetimeMs'),
    statusListLifetimeMs: bounded(options.statusListLifetimeMs, DAY, 10 * MINUTE, 30 * DAY, 'statusListLifetimeMs'),
    statusListTtlSeconds: bounded(options.statusListTtlSeconds, 300, 10, 86_400, 'statusListTtlSeconds'),
    recordRetentionMs: bounded(options.recordRetentionDays, 30, 1, 3650, 'recordRetentionDays') * DAY,
  };
}

const resolved = new WeakMap<object, ResolvedVcOptions | undefined>();
export function vcOptions(ctx: ServerContext): ResolvedVcOptions | undefined {
  if (!resolved.has(ctx.options))
    resolved.set(ctx.options, resolveVcOptions(ctx.options.verifiableCredentials));
  return resolved.get(ctx.options);
}
export function assertVc(ctx: ServerContext): ResolvedVcOptions {
  const options = vcOptions(ctx);
  if (!options)
    throw new IamError('FEATURE_DISABLED', 'Verifiable credentials are not enabled on this deployment', 403);
  return options;
}

export const credentialTypeResource = 'credential-type';
export const vcRequestAction = 'vc:request';

/** The catalog entries the module contributes when enabled: `credential-type` and `vc:request`. */
export function vcPlugins(options: { verifiableCredentials?: unknown }): IamPlugin[] {
  if (!resolveVcOptions(options.verifiableCredentials)) return [];
  return [
    {
      id: 'better-iam:verifiable-credentials',
      resourceTypes: {
        [credentialTypeResource]: {
          description: 'A kind of verifiable credential the organization issues: credential-type/{name}',
          actions: [vcRequestAction],
          attributes: { name: 'string', vct: 'string', requireMfa: 'boolean' },
        },
      },
    },
  ];
}

/** Where a claim's value comes from. */
export type VcClaimSource =
  | 'email'
  | 'emailVerified'
  | 'name'
  | 'identityId'
  | 'kind'
  | 'tenantId'
  | 'tenantName'
  | 'teams'
  | 'department'
  | 'static'
  | `attribute:${string}`;

export interface VcClaim {
  /** The claim name in the credential. */
  name: string;
  source: VcClaimSource;
  /** The value of a `static` claim. */
  value?: Json;
  /** Holders choose whether to reveal it (default true); false puts it in every presentation. */
  selective?: boolean;
  /** Refuse to issue when the value is missing (default false: the claim is left out). */
  required?: boolean;
  /** How wallets label it. */
  label?: string;
}

export interface VcCredentialType extends StoredRecord {
  name: string;
  displayName: string;
  description?: string;
  /** The credential type identifier (`vct`); by default `{issuer}/types/{name}`. */
  vct: string;
  claims: VcClaim[];
  lifetimeMs: number;
  /** People need an MFA session to get one for themselves. */
  requireMfa: boolean;
  enabled: boolean;
  /** Wallet card colors (`#rrggbb`). */
  backgroundColor?: string;
  textColor?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export type VcIssuerKeyStatus = 'active' | 'previous' | 'retired';
export interface VcIssuerKey extends StoredRecord {
  kid: string;
  status: VcIssuerKeyStatus;
  alg: 'ES256';
  publicJwk: JWK;
  keySealed: string;
  createdAt: number;
  createdBy: string;
  rotatedAt?: number;
  retiredAt?: number;
}

export type VcCredentialStatus = 'valid' | 'suspended' | 'revoked';
export interface VcIssuedCredential extends StoredRecord {
  typeId: string;
  typeName: string;
  vct: string;
  identityId: string;
  /** RFC 7638 thumbprint of the holder key the credential is bound to. */
  holderThumbprint: string;
  /** The `kid` of the issuer key that signed it. */
  keyId: string;
  statusListId: string;
  statusIndex: number;
  status: VcCredentialStatus;
  claimNames: string[];
  via: 'request' | 'offer' | 'admin';
  /** Who is answerable: the holder for self-service, the administrator who offered it otherwise. */
  issuedBy: string;
  /** Requested by the holder for themselves (re-decided by the sweep), with the MFA state of that session. */
  selfService: boolean;
  mfa: boolean;
  /** The wallet offer it was issued through. */
  offerId?: string;
  issuedAt: number;
  validUntil: number;
  revokedAt?: number;
  revokedBy?: string;
  reason?: string;
  /** When the record itself is swept: `validUntil` plus the record retention. */
  expiresAt: number;
}

export interface VcStatusList extends StoredRecord {
  size: number;
  bits: 2;
  /** Raw status entries, base64. */
  bytes: string;
  /** One bit per index handed out, base64 (indexes are never reused). */
  allocatedBits: string;
  allocated: number;
  version: number;
  createdAt: number;
  updatedAt: number;
}

/** A pre-authorized OpenID4VCI offer: one credential of one type for one identity. */
export interface VcOffer extends StoredRecord {
  typeId: string;
  identityId: string;
  codeHash: string;
  txCodeHash?: string;
  txCodeAttempts: number;
  /** For offers people make for themselves: whether the session had MFA (re-checked with policy at redemption). */
  selfService: boolean;
  mfa: boolean;
  createdAt: number;
  createdBy: string;
  redeemedAt?: number;
  accessTokenHash?: string;
  accessExpiresAt?: number;
  credentialId?: string;
  /** The offer's own end; after redemption, the access token's. */
  expiresAt: number;
}

interface VcNonce extends StoredRecord {
  expiresAt: number;
  usedAt?: number;
}

export const vcCollections = [
  'vcIssuerKeys',
  'vcCredentialTypes',
  'vcIssued',
  'vcStatusLists',
  'vcOffers',
  'vcNonces',
] as const;

/** The issuer identifier (and base URL of its endpoints) of a tenant. */
export function issuerUrl(ctx: ServerContext, tenantId: string): string {
  return `${ctx.config.baseURL.origin}${ctx.config.basePath}/vc/${tenantId}`;
}

const keyContext = (record: { id: string }) => `vc-issuer-key:${record.id}`;

export async function issuerKeys(tx: IamStore, tenantId: string): Promise<VcIssuerKey[]> {
  return (await tx.find<VcIssuerKey>('vcIssuerKeys', { tenantId })).sort(
    (a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1),
  );
}

export async function createIssuerKey(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  actorId: string,
): Promise<VcIssuerKey> {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = await exportJWK(publicKey);
  const jwk: JWK = { kty, crv, x, y };
  const kid = await calculateJwkThumbprint(jwk);
  const record: VcIssuerKey = {
    id: id(),
    tenantId,
    uniqueKey: kid,
    kid,
    status: 'active',
    alg: 'ES256',
    publicJwk: { ...jwk, kid, alg: 'ES256', use: 'sig' },
    keySealed: '',
    createdAt: ctx.now(),
    createdBy: actorId,
  };
  record.keySealed = encryptSecret(
    privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    ctx.options.secret,
    keyContext(record),
  );
  return tx.insert<VcIssuerKey>('vcIssuerKeys', record);
}

/** The active signing key, created on first use. */
export async function activeIssuerKey(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  actorId: string,
): Promise<VcIssuerKey> {
  return (
    (await issuerKeys(tx, tenantId)).find((key) => key.status === 'active') ??
    createIssuerKey(ctx, tx, tenantId, actorId)
  );
}

export function openIssuerKey(ctx: ServerContext, key: VcIssuerKey): KeyObject {
  const secrets = [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])];
  return createPrivateKey({
    key: Buffer.from(decryptSecret(key.keySealed, secrets, keyContext(key)), 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

/** The public keys verifiers accept: active and previous (retired keys verify nothing). */
export async function issuerJwks(tx: IamStore, tenantId: string): Promise<{ keys: JWK[] }> {
  return {
    keys: (await issuerKeys(tx, tenantId))
      .filter((key) => key.status !== 'retired')
      .map((key) => key.publicJwk),
  };
}

export async function typeByName(
  tx: IamStore,
  tenantId: string,
  name: string,
): Promise<VcCredentialType | undefined> {
  return (await tx.find<VcCredentialType>('vcCredentialTypes', { tenantId, uniqueKey: name }))[0];
}

export function typeResource(type: VcCredentialType): ResolvedResource {
  return {
    tenantId: type.tenantId,
    type: credentialTypeResource,
    id: type.name,
    attributes: { name: type.name, vct: type.vct, requireMfa: type.requireMfa },
  };
}

/** Resolves `credential-type/{name}` for the decision engine; undefined for other types. */
export async function resolveCredentialTypeResource(
  ctx: ServerContext,
  tx: IamStore,
  reference: { tenantId: string; type: string; id: string },
): Promise<ResolvedResource | undefined> {
  if (reference.type !== credentialTypeResource || !vcOptions(ctx)) return undefined;
  const type = await typeByName(tx, reference.tenantId, reference.id);
  if (!type) throw new IamError('NOT_FOUND', 'Unknown credential type', 404);
  return typeResource(type);
}

/** Whether a principal may request a type for themselves (`vc:request`), outside a root override from elsewhere. */
export async function mayRequest(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  type: VcCredentialType,
): Promise<boolean> {
  const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, vcRequestAction);
  if ('fixed' in prepared)
    return prepared.fixed.allowed && principal.identity.tenantId === tenant.id;
  return prepared.evaluate(typeResource(type), vcRequestAction).allowed;
}

const claimName = /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/;
const sources = new Set([
  'email',
  'emailVerified',
  'name',
  'identityId',
  'kind',
  'tenantId',
  'tenantName',
  'teams',
  'department',
  'static',
]);

/** Validates a type's claim list (1 to 32 claims, unique names, known sources). */
export function vcClaims(value: unknown, attributes: Record<string, unknown>): VcClaim[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32)
    throw new IamError('INVALID_INPUT', 'claims must list 1 to 32 claims');
  const seen = new Set<string>();
  return value.map((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
      throw new IamError('INVALID_INPUT', 'Each claim is an object');
    const item = raw as Record<string, unknown>;
    const name = item.name;
    if (typeof name !== 'string' || !claimName.test(name) || reservedVcClaims.has(name) || seen.has(name))
      throw new IamError('INVALID_INPUT', `Invalid, reserved or repeated claim name ${String(name).slice(0, 64)}`);
    seen.add(name);
    const source = item.source;
    const attribute = typeof source === 'string' && source.startsWith('attribute:') ? source.slice(10) : undefined;
    if (typeof source !== 'string' || (!sources.has(source) && !(attribute && Object.hasOwn(attributes, attribute))))
      throw new IamError('INVALID_INPUT', `Claim ${name} has an unknown source`);
    const claim: VcClaim = { name, source: source as VcClaimSource };
    if (source === 'static') {
      if (item.value === undefined || JSON.stringify(item.value).length > 2048)
        throw new IamError('INVALID_INPUT', `Static claim ${name} needs a value of at most 2 KiB`);
      if (JSON.stringify(item.value).match(/"(?:_sd|_sd_alg|\.\.\.)"\s*:/))
        throw new IamError('INVALID_INPUT', `Static claim ${name} may not contain _sd, _sd_alg or ... keys`);
      claim.value = item.value as Json;
    }
    if (item.selective !== undefined) {
      if (typeof item.selective !== 'boolean') throw new IamError('INVALID_INPUT', 'selective must be a boolean');
      claim.selective = item.selective;
    }
    if (item.required !== undefined) {
      if (typeof item.required !== 'boolean') throw new IamError('INVALID_INPUT', 'required must be a boolean');
      claim.required = item.required;
    }
    if (item.label !== undefined) {
      if (typeof item.label !== 'string' || !item.label.trim() || item.label.length > 64)
        throw new IamError('INVALID_INPUT', 'label must be 1-64 characters');
      claim.label = item.label;
    }
    return claim;
  });
}

/** The value of each claim for an identity; missing values are left out (required ones refuse). */
async function claimValues(
  tx: IamStore,
  tenant: Tenant,
  identity: Identity,
  type: VcCredentialType,
  at: number,
): Promise<{ plain: Record<string, unknown>; disclosable: Record<string, unknown> }> {
  const plain: Record<string, unknown> = {};
  const disclosable: Record<string, unknown> = {};
  for (const claim of type.claims) {
    let value: unknown;
    switch (claim.source) {
      case 'email':
        value = identity.email;
        break;
      case 'emailVerified':
        value = identity.email ? identity.emailVerified === true : undefined;
        break;
      case 'name':
        value = identity.name;
        break;
      case 'identityId':
        value = identity.id;
        break;
      case 'kind':
        value = identity.kind;
        break;
      case 'tenantId':
        value = tenant.id;
        break;
      case 'tenantName':
        value = tenant.name;
        break;
      case 'teams': {
        const names: string[] = [];
        for (const teamId of await teamsOf(tx, tenant.id, identity.id, { at })) {
          const team = await tx.get<{ id: string; tenantId: string; name?: string }>('teams', teamId);
          if (team?.tenantId === tenant.id && typeof team.name === 'string') names.push(team.name);
        }
        value = names.length ? names.sort() : undefined;
        break;
      }
      case 'department': {
        const departmentId = await departmentOf(tx, tenant.id, identity.id);
        const department = departmentId
          ? await tx.get<{ id: string; tenantId: string; name?: string }>('departments', departmentId)
          : undefined;
        value = department?.tenantId === tenant.id ? department.name : undefined;
        break;
      }
      case 'static':
        value = claim.value;
        break;
      default:
        value = identity.attributes?.[claim.source.slice('attribute:'.length)];
    }
    if (value === undefined || value === null || value === '') {
      if (claim.required)
        throw new IamError('CLAIM_UNAVAILABLE', `This person has no value for the claim ${claim.name}`, 409);
      continue;
    }
    (claim.selective === false ? plain : disclosable)[claim.name] = value;
  }
  return { plain, disclosable };
}

/** Hands out a fresh status index (random, never reused), opening a new list when the current one is half full. */
async function allocateStatus(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  options: ResolvedVcOptions,
): Promise<{ list: VcStatusList; index: number }> {
  const lists = (await tx.find<VcStatusList>('vcStatusLists', { tenantId })).sort(
    (a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1),
  );
  let list = lists.find((item) => item.allocated < item.size / 2);
  if (!list) {
    const now = ctx.now();
    list = await tx.insert<VcStatusList>('vcStatusLists', {
      id: id(),
      tenantId,
      size: options.statusListSize,
      bits: 2,
      bytes: Buffer.alloc(options.statusListSize / 4).toString('base64'),
      allocatedBits: Buffer.alloc(options.statusListSize / 8).toString('base64'),
      allocated: 0,
      version: 0,
      createdAt: now,
      updatedAt: now,
    });
  }
  const taken = Buffer.from(list.allocatedBits, 'base64');
  for (;;) {
    // Random indexes keep a credential's position from revealing when it was issued.
    const index = randomInt(list.size);
    const byte = index >> 3;
    const bit = 1 << (index & 7);
    if (taken[byte]! & bit) continue;
    taken[byte] = taken[byte]! | bit;
    const saved = await tx.put<VcStatusList>('vcStatusLists', {
      ...list,
      allocatedBits: taken.toString('base64'),
      allocated: list.allocated + 1,
      updatedAt: ctx.now(),
    });
    return { list: saved, index };
  }
}

/** Writes a credential's status into its list. */
export async function writeStatus(
  ctx: ServerContext,
  tx: IamStore,
  record: VcIssuedCredential,
  status: VcCredentialStatus,
): Promise<void> {
  const list = await tx.get<VcStatusList>('vcStatusLists', record.statusListId);
  if (!list || list.tenantId !== record.tenantId) throw new IamError('NOT_FOUND', 'Status list not found', 404);
  const bytes = Buffer.from(list.bytes, 'base64');
  setStatusAt(
    bytes,
    record.statusIndex,
    2,
    status === 'revoked' ? STATUS_INVALID : status === 'suspended' ? STATUS_SUSPENDED : STATUS_VALID,
  );
  await tx.put<VcStatusList>('vcStatusLists', {
    ...list,
    bytes: bytes.toString('base64'),
    version: list.version + 1,
    updatedAt: ctx.now(),
  });
}

/**
 * Issues one SD-JWT VC of `type` for `identity`, bound to `holderJwk`, and records it (status index allocated, audit
 * event `vc:credential:issue`). The lifetime never outlives the account's scheduled expiry nor `deadline` (the end of
 * the grant or session that allowed a self-service request).
 */
export async function issueCredential(
  ctx: ServerContext,
  tx: IamStore,
  input: {
    tenant: Tenant;
    type: VcCredentialType;
    identity: Identity;
    holderJwk: JWK;
    holderThumbprint: string;
    via: VcIssuedCredential['via'];
    actor: AuthenticatedPrincipal | { actorId: string };
    /** Who is answerable for it: the person for self-service, the administrator who made an offer for someone. */
    issuedBy: string;
    selfService: boolean;
    mfa: boolean;
    offerId?: string;
    deadline?: number;
  },
): Promise<{ credential: string; record: VcIssuedCredential }> {
  const options = assertVc(ctx);
  const { tenant, type, identity } = input;
  if (!type.enabled) throw new IamError('TYPE_DISABLED', 'This credential type is disabled', 409);
  if (identity.status !== 'active' || ctx.identityExpired(identity) || identity.tenantId !== tenant.id)
    throw new IamError('IDENTITY_INACTIVE', 'Credentials are issued to active members only', 409);
  const actorId = 'actorId' in input.actor ? input.actor.actorId : input.actor.identity.id;
  const key = await activeIssuerKey(ctx, tx, tenant.id, actorId);
  const now = ctx.now();
  const { plain, disclosable } = await claimValues(tx, tenant, identity, type, now);
  let validUntil = now + Math.min(type.lifetimeMs, options.maxLifetimeMs);
  if (typeof identity.expiresAt === 'number') validUntil = Math.min(validUntil, identity.expiresAt);
  if (input.deadline !== undefined) validUntil = Math.min(validUntil, input.deadline);
  if (validUntil < now + MINUTE)
    throw new IamError('ACCESS_EXPIRING', 'The access that allows this credential ends within a minute', 409);
  const { list, index } = await allocateStatus(ctx, tx, tenant.id, options);
  const issuer = issuerUrl(ctx, tenant.id);
  const { sdJwt } = await issueSdJwt({
    alg: 'ES256',
    kid: key.kid,
    key: openIssuerKey(ctx, key),
    typ: SD_JWT_VC_TYPE,
    plain: {
      ...plain,
      iss: issuer,
      iat: Math.floor(now / 1000),
      exp: Math.floor(validUntil / 1000),
      vct: type.vct,
      cnf: { jwk: input.holderJwk },
      status: { status_list: { idx: index, uri: `${issuer}/status/${list.id}` } },
    },
    disclosable,
    decoys: randomInt(4),
  });
  const record = await tx.insert<VcIssuedCredential>('vcIssued', {
    id: id(),
    tenantId: tenant.id,
    uniqueKey: `${list.id}:${index}`,
    typeId: type.id,
    typeName: type.name,
    vct: type.vct,
    identityId: identity.id,
    holderThumbprint: input.holderThumbprint,
    keyId: key.kid,
    statusListId: list.id,
    statusIndex: index,
    status: 'valid',
    claimNames: [...Object.keys(plain), ...Object.keys(disclosable)].sort(),
    via: input.via,
    issuedBy: input.issuedBy,
    selfService: input.selfService,
    mfa: input.mfa,
    ...(input.offerId ? { offerId: input.offerId } : {}),
    issuedAt: now,
    validUntil,
    expiresAt: validUntil + options.recordRetentionMs,
  });
  const metadata: Record<string, Json> = {
    type: type.name,
    credentialId: record.id,
    identityId: identity.id,
    issuedBy: input.issuedBy,
    holder: input.holderThumbprint,
    via: input.via,
    claims: record.claimNames,
    validUntil,
    ...(input.offerId ? { offerId: input.offerId } : {}),
  };
  if ('actorId' in input.actor)
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId: tenant.id,
      actorId,
      action: 'vc:credential:issue',
      resourceId: `vc/credentials/${record.id}`,
      outcome: 'allow',
      timestamp: now,
      metadata,
    });
  else
    await ctx.events.audit(tx, input.actor, 'vc:credential:issue', tenant.id, `vc/credentials/${record.id}`, 'allow', false, metadata);
  return { credential: sdJwt, record };
}

const NONCE_MS = 5 * MINUTE;
const nonceKeys = new WeakMap<object, Buffer>();
const nonceKey = (ctx: ServerContext) => {
  let key = nonceKeys.get(ctx.options);
  if (!key) nonceKeys.set(ctx.options, (key = createHash('sha256').update(`better-iam:vc-nonce:${ctx.options.secret}`).digest()));
  return key;
};
const nonceMac = (ctx: ServerContext, tenantId: string, issued: string, random: string) =>
  createHmac('sha256', nonceKey(ctx)).update(`${tenantId}.${issued}.${random}`).digest('base64url');

/**
 * A proof nonce (`c_nonce`) for one tenant, valid five minutes: stateless (`{time}.{random}.{mac}`), so handing them
 * out writes nothing; only using one records it, once.
 */
export function createNonce(ctx: ServerContext, tenantId: string): string {
  const issued = ctx.now().toString(36);
  const random = randomBytes(16).toString('base64url');
  return `${issued}.${random}.${nonceMac(ctx, tenantId, issued, random)}`;
}

/** Consumes a nonce; false when forged, expired, another tenant's, or used before. */
export async function consumeNonce(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  value: string | undefined,
): Promise<boolean> {
  const parts = typeof value === 'string' && value.length <= 128 ? value.split('.') : [];
  if (parts.length !== 3) return false;
  const [issued, random, mac] = parts as [string, string, string];
  const expected = Buffer.from(nonceMac(ctx, tenantId, issued, random));
  const given = Buffer.from(mac);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return false;
  const at = Number.parseInt(issued, 36);
  const now = ctx.now();
  if (!Number.isSafeInteger(at) || at > now + MINUTE || now - at > NONCE_MS) return false;
  const recordId = hash(`vc-nonce:${value}`);
  if (await tx.get<VcNonce>('vcNonces', recordId)) return false;
  await tx.insert<VcNonce>('vcNonces', { id: recordId, tenantId, expiresAt: at + NONCE_MS, usedAt: now });
  return true;
}

/** Checks an OpenID4VCI proof for the tenant's issuer and consumes its nonce; returns the holder key. */
export async function holderFromProof(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  proof: unknown,
): Promise<{ jwk: JWK; thumbprint: string }> {
  let checked: Awaited<ReturnType<typeof verifyHolderProof>>;
  try {
    checked = await verifyHolderProof(proof, { audience: issuerUrl(ctx, tenantId), now: ctx.now() });
  } catch (error) {
    throw new IamError('INVALID_PROOF', (error as Error).message, 400);
  }
  if (!(await consumeNonce(ctx, tx, tenantId, checked.nonce)))
    throw new IamError('INVALID_NONCE', 'The proof needs a fresh nonce from verifiableCredentials.nonce', 400);
  return { jwk: checked.jwk, thumbprint: checked.thumbprint };
}

/** Signed Status List Tokens, cached per list version and signing key until half their cache time passed. */
const statusTokens = new WeakMap<object, Map<string, { token: string; at: number }>>();
export async function statusListToken(ctx: ServerContext, reader: IamStore, list: VcStatusList): Promise<string> {
  const options = assertVc(ctx);
  // A list exists only after a credential was issued, and with it the key: reads never create one.
  const key = (await issuerKeys(reader, list.tenantId)).find((item) => item.status === 'active');
  if (!key) throw new IamError('NOT_FOUND', 'No issuer key', 404);
  let cache = statusTokens.get(ctx.options);
  if (!cache) statusTokens.set(ctx.options, (cache = new Map()));
  const cacheKey = `${list.id}:${list.version}:${key.kid}`;
  const now = ctx.now();
  const hit = cache.get(cacheKey);
  if (hit && now - hit.at < (options.statusListTtlSeconds * 1000) / 2 && now >= hit.at) return hit.token;
  const signed = await signStatusList({
    uri: `${issuerUrl(ctx, list.tenantId)}/status/${list.id}`,
    bytes: Buffer.from(list.bytes, 'base64'),
    bits: 2,
    alg: 'ES256',
    kid: key.kid,
    key: openIssuerKey(ctx, key),
    issuedAt: now,
    expiresAt: now + options.statusListLifetimeMs,
    ttlSeconds: options.statusListTtlSeconds,
  });
  if (cache.size > 1000) cache.clear();
  cache.set(cacheKey, { token: signed, at: now });
  return signed;
}

export interface VerifiedCredential extends VerifiedSdJwt {
  tenantId: string;
  /** The credential type, when the issuer is a tenant of this deployment and still has it. */
  type?: string;
  status: { index: number; uri: string };
}

/**
 * Verifies a presentation of a credential this deployment issued: the tenant's keys, disclosures, key binding (for
 * `audience` and `nonce`, both required unless `requireKeyBinding: false`) and the credential's current standing:
 * revoked and suspended credentials fail, and so do those of holders who are no longer active members or of an
 * organization that is suspended (even before the sweep revokes them). Reads only, outside any transaction.
 */
export async function verifyLocalPresentation(
  ctx: ServerContext,
  presentation: string,
  options: { audience?: string; nonce?: string; requireKeyBinding?: boolean; tenantId?: string },
): Promise<VerifiedCredential> {
  assertVc(ctx);
  if (options.requireKeyBinding !== false && (options.audience === undefined || options.nonce === undefined))
    throw new IamError(
      'INVALID_INPUT',
      'Verify a presentation for your audience and the nonce you issued; without them it could be a replay',
    );
  const reader = ctx.store;
  const prefix = `${ctx.config.baseURL.origin}${ctx.config.basePath}/vc/`;
  let tenantId = '';
  const verified = await verifySdJwt(presentation, {
    issuerKey: async (kid, issuer) => {
      if (!issuer.startsWith(prefix)) return undefined;
      tenantId = issuer.slice(prefix.length);
      if (!tenantId || tenantId.includes('/') || (options.tenantId && options.tenantId !== tenantId)) return undefined;
      const key = (await issuerKeys(reader, tenantId)).find((item) => item.kid === kid && item.status !== 'retired');
      return key?.publicJwk;
    },
    now: ctx.now(),
    requireKeyBinding: options.requireKeyBinding,
    ...(options.audience !== undefined ? { audience: options.audience } : {}),
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
  });
  const reference = verified.status;
  const statusPrefix = `${issuerUrl(ctx, tenantId)}/status/`;
  const listId = reference?.uri.startsWith(statusPrefix) ? reference.uri.slice(statusPrefix.length) : undefined;
  const list = listId ? await reader.get<VcStatusList>('vcStatusLists', listId) : undefined;
  if (!reference || !list || list.tenantId !== tenantId)
    throw new SdJwtError('status-unavailable', 'The credential has no status this issuer knows');
  const status = statusAt(Buffer.from(list.bytes, 'base64'), reference.index, 2);
  if (status === STATUS_INVALID) throw new SdJwtError('revoked', 'The credential was revoked');
  if (status === STATUS_SUSPENDED) throw new SdJwtError('suspended', 'The credential is suspended');
  if (status !== STATUS_VALID) throw new SdJwtError('status-unavailable', 'The credential status is unknown');
  const record = (
    await reader.find<VcIssuedCredential>('vcIssued', { tenantId, uniqueKey: `${list.id}:${reference.index}` })
  )[0];
  if (!record) throw new SdJwtError('status-unavailable', 'The credential is unknown to this issuer');
  const identity = await reader.get<Identity>('identities', record.identityId);
  if (!identity || identity.status !== 'active' || ctx.identityExpired(identity))
    throw new SdJwtError('revoked', 'The holder is no longer a member');
  const tenant = await reader.get<Tenant>('tenants', tenantId);
  if (!tenant || (await ctx.ancestry(reader, tenant)).some((item) => item.status !== 'active'))
    throw new SdJwtError('suspended', 'The issuing organization is suspended');
  return { ...verified, tenantId, status: reference, type: record.typeName };
}

export interface VcSweepResult {
  examined: number;
  revoked: number;
}

/**
 * Revokes valid credentials whose holder is no longer an active member, and self-service ones whose holder may no
 * longer request them (`vc:request` decided again, with the MFA state of the issuing session). A scheduler job; each
 * tenant in its own transaction.
 */
export async function sweepCredentials(ctx: ServerContext, input: { tenantId?: string } = {}): Promise<VcSweepResult> {
  assertVc(ctx);
  const result: VcSweepResult = { examined: 0, revoked: 0 };
  const now = ctx.now();
  const tenantIds = input.tenantId
    ? [input.tenantId]
    : [
        ...new Set(
          (await ctx.store.find<VcIssuedCredential>('vcIssued', { status: 'valid' }))
            .filter((record) => record.validUntil > now)
            .map((record) => record.tenantId),
        ),
      ];
  for (const tenantId of tenantIds)
    await ctx.store.transaction(async (tx) => {
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (!tenant) return;
      const records = (await tx.find<VcIssuedCredential>('vcIssued', { tenantId, status: 'valid' })).filter(
        (record) => record.validUntil > now,
      );
      const types = new Map<string, VcCredentialType | undefined>();
      for (const record of records) {
        result.examined++;
        const identity = await tx.get<Identity>('identities', record.identityId);
        let reason: string | undefined;
        if (!identity || identity.status !== 'active' || ctx.identityExpired(identity)) reason = 'identity-inactive';
        else if (record.selfService) {
          if (!types.has(record.typeId)) types.set(record.typeId, await tx.get<VcCredentialType>('vcCredentialTypes', record.typeId));
          const type = types.get(record.typeId);
          const principal = ctx.decisions.simulatedPrincipal(identity, record.mfa === true);
          // Only a clear refusal revokes: a suspended organization's credentials already fail verification.
          const allowed =
            !!type && (!type.requireMfa || record.mfa === true) && (await mayRequest(ctx, tx, principal, tenant, type));
          const suspended = (await ctx.ancestry(tx, tenant)).some((item) => item.status !== 'active');
          if (!allowed && !suspended) reason = 'access-changed';
        }
        if (!reason) continue;
        await writeStatus(ctx, tx, record, 'revoked');
        await tx.put<VcIssuedCredential>('vcIssued', {
          ...record,
          status: 'revoked',
          revokedAt: now,
          revokedBy: 'deployment-operator',
          reason,
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'vc:credential:revoke',
          resourceId: `vc/credentials/${record.id}`,
          outcome: 'allow',
          timestamp: now,
          metadata: { reason, identityId: record.identityId },
        });
        result.revoked++;
      }
    });
  return result;
}

/** Pre-authorized codes and access tokens name their offer: `biam_vco.{offerId}.{secret}` / `biam_vcat.…`. */
export function offerToken(prefix: 'biam_vco' | 'biam_vcat', offerId: string): string {
  return `${prefix}.${offerId}.${randomBytes(32).toString('base64url')}`;
}
export function offerIdOf(value: unknown, prefix: 'biam_vco' | 'biam_vcat'): string | undefined {
  const parts = typeof value === 'string' && value.length <= 256 ? value.split('.') : [];
  return parts.length === 3 && parts[0] === prefix && parts[1] && parts[2] ? parts[1] : undefined;
}
export const matchesHash = (stored: string | undefined, value: string) =>
  typeof stored === 'string' && sameHash(stored, hash(value));
