import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
  CompactSign,
  compactVerify,
  decodeProtectedHeader,
  FlattenedSign,
  importJWK,
  type JWK,
  type ProtectedHeaderParameters,
} from 'jose';
import {
  canonicalizeJson,
  delegationTokenType,
  IamError,
  readDelegationTokenClaims,
  type DelegationTokenSummary,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import { tokenStillStands, type DelegationTokenRecord } from './delegation-tokens.js';

/**
 * IAM-attested A2A agent cards. An agent's A2A server builds its agent card (the Agent2Agent protocol's
 * `/.well-known/agent-card.json`) and asks Better IAM to sign it (`agents.signCard`). IAM checks that the card's
 * endpoints belong to the agent's registered `url`, sets the card's `provider.organization` to the tenant, adds an
 * attestation extension (who the agent is, which organization runs it, that a person sponsors it, when the
 * attestation expires), and signs the canonical card (RFC 8785) as a detached JWS, the A2A card signature format.
 * Anyone holding the deployment's card keys (`iam.a2a.jwks()`, published at `a2a.jwksUrl`) can then check that a
 * remote agent is a registered agent in good standing of a given organization (`verifyAgentCard` in `@better-iam/a2a`).
 */

/** The URI of the attestation extension IAM adds to `capabilities.extensions` of every card it signs. */
export const agentAttestationUri = 'urn:better-iam:a2a:attestation:v1';

export interface A2aOptions {
  /**
   * Private JWKs (1 to 10) that sign agent cards: `kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA'` or `kty: 'EC',
   * crv: 'P-256', alg: 'ES256'`, each with a unique `kid` (/^[A-Za-z0-9._-]{1,64}$/). Use keys of their own, not
   * the `sts.jwt` session keys.
   */
  signingKeys: JWK[];
  /** The `kid` cards are signed with (default: the first signing key). */
  activeKeyId?: string;
  /** Public-only retired keys (0 to 10) that are still published so cards they signed keep verifying. */
  verificationKeys?: JWK[];
  /** Where the deployment publishes `iam.a2a.jwks()`: carried as `jku` in every card signature. */
  jwksUrl?: string;
  /** How long an attestation is valid, 300 to 604800 seconds (default 3600). Re-sign before it expires. */
  cardLifetimeSeconds?: number;
  /** The attestation's `issuer` (default: the deployment's base URL and base path). */
  issuer?: string;
}

/** The attestation IAM adds to a card, as the params of the `agentAttestationUri` extension. */
export interface AgentAttestation {
  issuer: string;
  tenantId: string;
  /** The tenant's name; also the card's `provider.organization`. */
  organization: string;
  agentId: string;
  agentName: string;
  /** Always true: IAM signs cards only for agents whose sponsor is an active person. */
  sponsored: true;
  /** Whether people may delegate to the agent. */
  delegable: boolean;
  model?: string;
  provider?: string;
  protocols?: string[];
  /** ISO 8601 times; verifiers refuse the card after `expiresAt`. */
  issuedAt: string;
  expiresAt: string;
}

/** A public card-signing key, as published in the JWKS. */
export interface PublicCardJwk {
  kty: 'OKP' | 'EC';
  crv: 'Ed25519' | 'P-256';
  x: string;
  y?: string;
  kid: string;
  alg: 'EdDSA' | 'ES256';
  use: 'sig';
}

/** A card IAM signed: the input card with IAM's provider, attestation extension and one JWS signature. */
export interface SignedAgentCard {
  card: Record<string, unknown> & {
    signatures: { protected: string; signature: string }[];
  };
  attestation: AgentAttestation;
  /** Epoch milliseconds; re-sign before then. */
  expiresAt: number;
}

interface CardKey {
  jwk: JWK;
  kid: string;
  alg: 'EdDSA' | 'ES256';
  publicJwk: PublicCardJwk;
}

interface CardSigner {
  issuer: string;
  jwksUrl?: string;
  lifetimeSeconds: number;
  jwks: { keys: PublicCardJwk[] };
  sign(payload: Uint8Array): Promise<{ protected: string; signature: string }>;
  /** Signs `claims` as a compact JWT with the active key and an explicit `typ` (never `JOSE`, the card type). */
  signJwt(claims: Record<string, unknown>, typ: string): Promise<string>;
  /** Verifies a compact JWT of type `typ` with the published keys; the payload, or undefined when it does not verify. */
  verifyJwt(token: string, typ: string): Promise<Record<string, unknown> | undefined>;
}

const kidPattern = /^[A-Za-z0-9._-]{1,64}$/;
const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;
const maxCardBytes = 64 * 1024;

function invalid(detail: string): never {
  throw new IamError('INVALID_CONFIG', `a2a.${detail}`);
}

function cardKey(value: unknown, field: string, signing: boolean): CardKey {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid(`${field} must contain JWK objects`);
  const jwk = value as JWK & Record<string, unknown>;
  const alg =
    jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.alg === 'EdDSA'
      ? 'EdDSA'
      : jwk.kty === 'EC' && jwk.crv === 'P-256' && jwk.alg === 'ES256'
        ? 'ES256'
        : undefined;
  if (!alg)
    invalid(`${field} keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256`);
  if (typeof jwk.kid !== 'string' || !kidPattern.test(jwk.kid))
    invalid(`${field} keys need a kid matching /^[A-Za-z0-9._-]{1,64}$/`);
  if (jwk.use !== undefined && jwk.use !== 'sig') invalid(`${field} keys must have use 'sig'`);
  if (typeof jwk.x !== 'string' || (alg === 'ES256' && typeof jwk.y !== 'string'))
    invalid(`${field} keys need their public coordinates`);
  if (signing) {
    if (typeof jwk.d !== 'string') invalid(`${field} must contain private keys`);
  } else if (privateMembers.some((member) => jwk[member] !== undefined))
    invalid(`${field} must contain public keys only`);
  const material: JWK = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    ...(alg === 'ES256' ? { y: jwk.y } : {}),
    ...(signing ? { d: jwk.d } : {}),
  };
  try {
    if (signing) {
      const derived = createPublicKey(
        createPrivateKey({ key: material as never, format: 'jwk' }),
      ).export({ format: 'jwk' });
      if (derived.x !== jwk.x || (alg === 'ES256' && derived.y !== jwk.y)) throw new Error();
    } else createPublicKey({ key: material as never, format: 'jwk' });
  } catch {
    invalid(`${field} key ${jwk.kid} is not a valid ${alg} key`);
  }
  return {
    jwk: material,
    kid: jwk.kid,
    alg,
    publicJwk: {
      kty: jwk.kty as PublicCardJwk['kty'],
      crv: jwk.crv as PublicCardJwk['crv'],
      x: jwk.x,
      ...(alg === 'ES256' ? { y: jwk.y as string } : {}),
      kid: jwk.kid,
      alg,
      use: 'sig',
    },
  };
}

function httpUrl(value: unknown, field: string): string {
  let url: URL | undefined;
  try {
    url = typeof value === 'string' ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  if (
    !url ||
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.username ||
    url.password
  )
    invalid(`${field} must be an absolute http(s) URL without credentials`);
  return value as string;
}

function createCardSigner(ctx: ServerContext): CardSigner | undefined {
  const options = ctx.options.a2a;
  if (options === undefined) return undefined;
  if (!options || typeof options !== 'object') invalid('options must be an object');
  const signingKeys = options.signingKeys as unknown;
  if (!Array.isArray(signingKeys) || signingKeys.length < 1 || signingKeys.length > 10)
    invalid('signingKeys must contain 1 to 10 keys');
  const verificationKeys = (options.verificationKeys ?? []) as unknown;
  if (!Array.isArray(verificationKeys) || verificationKeys.length > 10)
    invalid('verificationKeys must contain at most 10 keys');
  const signing = signingKeys.map((key) => cardKey(key, 'signingKeys', true));
  const retired = verificationKeys.map((key) => cardKey(key, 'verificationKeys', false));
  const kids = new Set<string>();
  for (const key of [...signing, ...retired]) {
    if (kids.has(key.kid)) invalid(`kid ${key.kid} is used more than once`);
    kids.add(key.kid);
  }
  const active = signing.find((key) => key.kid === (options.activeKeyId ?? signing[0]!.kid));
  if (!active) invalid('activeKeyId must name one of the signing keys');
  const lifetimeSeconds = options.cardLifetimeSeconds ?? 3600;
  if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 300 || lifetimeSeconds > 604_800)
    invalid('cardLifetimeSeconds must be an integer from 300 to 604800');
  const issuer =
    options.issuer !== undefined
      ? httpUrl(options.issuer, 'issuer')
      : `${ctx.config.baseURL.origin}${ctx.config.basePath}`;
  const jwksUrl = options.jwksUrl !== undefined ? httpUrl(options.jwksUrl, 'jwksUrl') : undefined;
  let key: ReturnType<typeof importJWK> | undefined;
  const privateKey = () =>
    (key ??= importJWK(active.jwk, active.alg).catch((error: unknown) => {
      key = undefined;
      throw error;
    }));
  const all = [...signing, ...retired];
  const publicKeys = new Map<string, ReturnType<typeof importJWK>>();
  return {
    issuer,
    ...(jwksUrl ? { jwksUrl } : {}),
    lifetimeSeconds,
    jwks: { keys: all.map((item) => item.publicJwk) },
    async sign(payload) {
      const jws = await new FlattenedSign(payload)
        .setProtectedHeader({
          alg: active.alg,
          kid: active.kid,
          typ: 'JOSE',
          ...(jwksUrl ? { jku: jwksUrl } : {}),
        })
        .sign(await privateKey());
      return { protected: jws.protected!, signature: jws.signature };
    },
    async signJwt(claims, typ) {
      return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
        .setProtectedHeader({
          alg: active.alg,
          kid: active.kid,
          typ,
          ...(jwksUrl ? { jku: jwksUrl } : {}),
        })
        .sign(await privateKey());
    },
    async verifyJwt(token, typ) {
      let header: ProtectedHeaderParameters;
      try {
        header = decodeProtectedHeader(token);
      } catch {
        return undefined;
      }
      const found = all.find((item) => item.kid === header.kid && item.alg === header.alg);
      if (!found || header.typ !== typ || header.crit !== undefined) return undefined;
      let publicKey = publicKeys.get(found.kid);
      if (!publicKey) {
        publicKey = importJWK(found.publicJwk as JWK, found.alg);
        publicKeys.set(found.kid, publicKey);
      }
      try {
        const { payload } = await compactVerify(token, await publicKey, {
          algorithms: [found.alg],
        });
        const claims: unknown = JSON.parse(new TextDecoder().decode(payload));
        return plain(claims) ? claims : undefined;
      } catch {
        return undefined;
      }
    },
  };
}

const signers = new WeakMap<ServerContext, { signer: CardSigner | undefined }>();

/** The deployment's card signer, validated once per context; undefined without the `a2a` option. */
export function cardSigner(ctx: ServerContext): CardSigner | undefined {
  let found = signers.get(ctx);
  if (!found) {
    found = { signer: createCardSigner(ctx) };
    signers.set(ctx, found);
  }
  return found.signer;
}

const plain = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

function refuse(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}

/** The origin of a card endpoint, refusing anything but an http(s) URL on the agent's registered origin. */
function endpointOn(value: unknown, field: string, origin: string): string {
  let url: URL | undefined;
  try {
    url = typeof value === 'string' ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  if (!url || (url.protocol !== 'https:' && url.protocol !== 'http:'))
    refuse(`${field} must be an http(s) URL`);
  if (url.origin !== origin)
    refuse(`${field} must be on the agent's registered origin ${origin} (set the agent's url)`);
  return value as string;
}

/**
 * Signs `input` for `agent`: an A2A agent card whose `url` (and every `additionalInterfaces[].url`) is on the origin
 * of the agent's registered `url`. The caller has already been authorized; the agent must be in good standing.
 */
export async function signAgentCard(
  ctx: ServerContext,
  tenant: Tenant,
  agent: Identity,
  input: unknown,
): Promise<SignedAgentCard> {
  const signer = cardSigner(ctx);
  if (!signer)
    throw new IamError('FEATURE_DISABLED', 'Agent card signing is not enabled (a2a option)', 403);
  const profile = agent.agent;
  if (!profile?.url) refuse('Register the agent’s url before signing its card');
  if (!plain(input)) refuse('card must be an A2A agent card object');
  const origin = new URL(profile.url).origin;
  const { signatures: _dropped, ...card } = input;
  if (typeof card.name !== 'string' || !card.name.trim() || card.name.length > 256)
    refuse('card.name must be 1-256 characters');
  endpointOn(card.url, 'card.url', origin);
  // Every endpoint the card offers (A2A 0.3 `additionalInterfaces`, 1.0 `supportedInterfaces`) is pinned the same way.
  for (const field of ['additionalInterfaces', 'supportedInterfaces'] as const) {
    const interfaces = card[field];
    if (interfaces === undefined) continue;
    if (!Array.isArray(interfaces) || interfaces.length > 16)
      refuse(`card.${field} must list at most 16 interfaces`);
    interfaces.forEach((item: unknown, index) => {
      if (!plain(item)) refuse(`card.${field}[${index}] must be an object`);
      endpointOn(item.url, `card.${field}[${index}].url`, origin);
    });
  }
  if (card.capabilities !== undefined && !plain(card.capabilities))
    refuse('card.capabilities must be an object');
  const capabilities = { ...((card.capabilities as Record<string, unknown> | undefined) ?? {}) };
  if (capabilities.extensions !== undefined && !Array.isArray(capabilities.extensions))
    refuse('card.capabilities.extensions must be an array');
  const now = ctx.now();
  const expiresAt = now + signer.lifetimeSeconds * 1000;
  const attestation: AgentAttestation = {
    issuer: signer.issuer,
    tenantId: tenant.id,
    organization: tenant.name,
    agentId: agent.id,
    agentName: agent.name,
    sponsored: true,
    delegable: profile.delegable !== false,
    ...(profile.model !== undefined ? { model: profile.model } : {}),
    ...(profile.provider !== undefined ? { provider: profile.provider } : {}),
    ...(profile.protocols?.length ? { protocols: [...profile.protocols] } : {}),
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
  };
  const unsigned: Record<string, unknown> = {
    ...card,
    // The provider is the organization, reached at the agent's registered origin (never a URL the card chose).
    provider: { organization: tenant.name, url: origin },
    capabilities: {
      ...capabilities,
      // Any attestation already in the card is dropped: only IAM's own, signed below, may stand.
      extensions: [
        ...((capabilities.extensions as unknown[] | undefined) ?? []).filter(
          (item) => !plain(item) || item.uri !== agentAttestationUri,
        ),
        {
          uri: agentAttestationUri,
          description: 'This agent is registered with, and attested by, Better IAM.',
          required: false,
          params: attestation,
        },
      ],
    },
  };
  let canonical: string;
  try {
    canonical = canonicalizeJson(unsigned);
  } catch {
    refuse('card must be plain JSON');
  }
  if (new TextEncoder().encode(canonical).byteLength > maxCardBytes)
    refuse('card must be at most 64 KiB');
  const signature = await signer.sign(new TextEncoder().encode(canonical));
  return {
    // A copy of exactly what was signed, sharing nothing with the input.
    card: {
      ...(JSON.parse(canonical) as Record<string, unknown>),
      signatures: [signature],
    },
    attestation,
    expiresAt,
  };
}

/** `iam.a2a`: the card-signing keys, for the route that publishes them. */
export interface A2aRuntime {
  /** Whether cards can be signed (the `a2a` option is set). */
  readonly enabled: boolean;
  /** The public card keys (signing and retired), for verifiers. Empty without the `a2a` option. */
  jwks(): { keys: PublicCardJwk[] };
  /** A GET response publishing `jwks()`, cacheable for five minutes: serve it at `a2a.jwksUrl`. */
  jwksResponse(): Response;
  /**
   * Verifies a delegation token (`delegations.issueToken`) this deployment issued, for a service running next to it:
   * the signature with the deployment's keys, the type, the issuer, `audience`, `tenantId` when given, and the times.
   * With `live`, also that everything it stands on is still in place (the delegation chain, the person, the agents and
   * the agent's key, the audience and the scopes), so a revocation takes effect before the token expires. Throws
   * DELEGATION_TOKEN_INVALID (401).
   */
  verifyDelegationToken(
    token: string,
    options: VerifyIssuedDelegationTokenOptions,
  ): Promise<DelegationTokenSummary>;
}

export interface VerifyIssuedDelegationTokenOptions {
  /** The audience the service answers to: the token's `aud` must be exactly this. */
  audience: string;
  /** Accept only tokens of this organization. */
  tenantId?: string;
  /**
   * Also re-check in storage everything the token stands on: the delegation chain, the person, the agents and the
   * agent's key in good standing, the audience still allowed, and the scopes still allowed by every limit.
   */
  live?: boolean;
  /** Records a verified token id until it expires; return false when it was seen before to refuse the replay. */
  replay?: (tokenId: string, expiresAt: number) => boolean | Promise<boolean>;
  /** Allowed clock difference in seconds (default 30). */
  clockToleranceSeconds?: number;
}

/** Validates the `a2a` option at construction (INVALID_CONFIG) and exposes the public keys. */
export function createA2aRuntime(ctx: ServerContext): A2aRuntime {
  const signer = cardSigner(ctx);
  const jwks = () => ({ keys: (signer?.jwks.keys ?? []).map((key) => ({ ...key })) });
  const invalidToken = (message: string) => new IamError('DELEGATION_TOKEN_INVALID', message, 401);
  return {
    enabled: !!signer,
    async verifyDelegationToken(token, options) {
      if (!signer)
        throw new IamError('FEATURE_DISABLED', 'Delegation tokens need the a2a option', 403);
      if (typeof token !== 'string' || token.length > 16_384)
        throw invalidToken('Not a delegation token');
      const claims = await signer.verifyJwt(token, delegationTokenType);
      if (!claims) throw invalidToken('The delegation token does not verify');
      const read = readDelegationTokenClaims(claims, {
        issuer: signer.issuer,
        audience: options.audience,
        now: ctx.now(),
        ...(options.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
        ...(options.clockToleranceSeconds !== undefined
          ? { clockToleranceSeconds: options.clockToleranceSeconds }
          : {}),
      });
      if ('rejected' in read) throw invalidToken(read.message);
      const verified = read.token;
      if (options.live)
        await ctx.store.transaction(async (tx) => {
          // The record kept at issue time: the token's own key, audience, scopes and session limits.
          const record = await tx.get<DelegationTokenRecord>('delegationTokens', verified.tokenId);
          if (
            !record ||
            record.tenantId !== verified.tenantId ||
            record.delegationId !== verified.delegationId ||
            record.personId !== verified.personId ||
            record.agentId !== verified.agentId ||
            record.audience !== verified.audience ||
            record.scopes.join(' ') !== verified.scopes.join(' ') ||
            !(await tokenStillStands(ctx, tx, record, ctx.now()))
          )
            throw invalidToken('What the delegation token stands on is no longer in place');
        });
      if (options.replay && !(await options.replay(verified.tokenId, verified.expiresAt)))
        throw invalidToken('The delegation token was used before');
      return verified;
    },
    jwks,
    jwksResponse: () =>
      Response.json(jwks(), {
        headers: {
          'content-type': 'application/jwk-set+json',
          'cache-control': 'public, max-age=300',
          'access-control-allow-origin': '*',
        },
      }),
  };
}
