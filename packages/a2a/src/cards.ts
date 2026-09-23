import { canonicalizeJson } from '@better-iam/core';

/**
 * Agent2Agent (A2A) agent cards: the types the helpers read, verification of cards Better IAM attested
 * (`agents.signCard`), discovery of a remote agent's card, and an attestor that keeps an agent's own card signed.
 */

export interface AgentSkill {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
  security?: Record<string, string[]>[];
  [key: string]: unknown;
}

export interface AgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;
}

/** One JWS signature of a card (RFC 7515 JSON serialization, detached payload). */
export interface AgentCardSignature {
  protected: string;
  signature: string;
  header?: Record<string, unknown>;
}

/** An A2A agent card (`/.well-known/agent-card.json`). */
export interface AgentCard {
  protocolVersion?: string;
  name: string;
  description?: string;
  url: string;
  preferredTransport?: string;
  additionalInterfaces?: { url: string; transport: string }[];
  provider?: { organization: string; url: string };
  iconUrl?: string;
  version?: string;
  documentationUrl?: string;
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    stateTransitionHistory?: boolean;
    extensions?: AgentExtension[];
  };
  securitySchemes?: Record<string, Record<string, unknown>>;
  security?: Record<string, string[]>[];
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills?: AgentSkill[];
  supportsAuthenticatedExtendedCard?: boolean;
  signatures?: AgentCardSignature[];
  [key: string]: unknown;
}

/** The URI of the attestation extension Better IAM adds to every card it signs. */
export const agentAttestationUri = 'urn:better-iam:a2a:attestation:v1';

/** What Better IAM attests about an agent (the params of the attestation extension). */
export interface AgentAttestation {
  issuer: string;
  tenantId: string;
  organization: string;
  agentId: string;
  agentName: string;
  sponsored: true;
  delegable: boolean;
  model?: string;
  provider?: string;
  protocols?: string[];
  issuedAt: string;
  expiresAt: string;
}

/** A public card key (`iam.a2a.jwks()`). */
export interface CardJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  alg?: string;
  use?: string;
}
export interface CardJwks {
  keys: CardJwk[];
}

export type AgentCardErrorReason =
  | 'malformed'
  | 'unsigned'
  | 'untrusted-key'
  | 'signature'
  | 'attestation'
  | 'expired'
  | 'issuer'
  | 'tenant'
  | 'endpoint'
  | 'fetch';

/**
 * Why an agent card was refused by `verifyAgentCard` or `discoverAgent`: `reason` is `unsigned`, `untrusted-key`,
 * `signature`, `attestation`, `expired`, `issuer`, `tenant`, `endpoint`, `malformed` or `fetch`.
 */
export class AgentCardError extends Error {
  constructor(
    public readonly reason: AgentCardErrorReason,
    message: string,
  ) {
    super(message);
    this.name = 'AgentCardError';
  }
}

export interface VerifyAgentCardOptions {
  /**
   * The Better IAM deployments you trust, by attestation issuer: each issuer's JWKS URL (`a2a.jwksUrl`) or its JWKS.
   * The card is checked only with the keys of the issuer it names, so one trusted deployment cannot vouch in another's
   * name. The safest choice when you trust more than one deployment; otherwise give `keys` or `trustedJwksUrls`.
   */
  trustedIssuers?: Record<string, string | CardJwks>;
  /**
   * The card keys of a Better IAM deployment you trust: a JWKS (`iam.a2a.jwks()`), or a function returning the JWKS for
   * a signature's `kid` and `jku`.
   */
  keys?: CardJwks | ((kid: string, jku: string | undefined) => Promise<CardJwks> | CardJwks);
  /**
   * JWKS URLs you trust (`a2a.jwksUrl` of those deployments). A signature is checked only when its `jku` is exactly
   * one of them; the key set is fetched with `fetch` and cached for `jwksCacheSeconds` (fetched again, at most every
   * 30 seconds, when a signature names a key it does not have).
   */
  trustedJwksUrls?: string[];
  /** Attestation issuers you accept; default: any whose key verifies. */
  issuers?: string[];
  /** Accept only agents attested for this tenant (organization). */
  tenantId?: string;
  /** Require the card's `url` to be on this origin (discovery passes the origin it fetched from). */
  origin?: string;
  /** Allowed clock difference in seconds (default 60). */
  clockToleranceSeconds?: number;
  /** How long fetched key sets are kept, in seconds (default 300). */
  jwksCacheSeconds?: number;
  now?: () => number;
  fetch?: typeof fetch;
}

export interface VerifiedAgentCard {
  card: AgentCard;
  attestation: AgentAttestation;
  /** The `kid` of the key that verified the card. */
  kid: string;
}

const base64UrlPattern = /^[A-Za-z0-9_-]*$/;

/** @internal Shared with delegation-tokens.ts; not exported from the package. */
export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!base64UrlPattern.test(value)) throw new AgentCardError('malformed', 'Invalid base64url');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000)
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** @internal */
export const plain = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

/** @internal */
export async function verifySignature(
  jwk: CardJwk,
  alg: string,
  signingInput: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  const subtle = globalThis.crypto.subtle;
  const material = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ...(jwk.y ? { y: jwk.y } : {}) };
  try {
    if (alg === 'EdDSA' && jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
      const key = await subtle.importKey('jwk', material, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, signature, signingInput);
    }
    if (alg === 'ES256' && jwk.kty === 'EC' && jwk.crv === 'P-256') {
      const key = await subtle.importKey(
        'jwk',
        material,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, signingInput);
    }
  } catch {
    return false;
  }
  return false;
}

function attestationOf(card: AgentCard): AgentAttestation {
  const found = (card.capabilities?.extensions ?? []).filter(
    (item) => plain(item) && item.uri === agentAttestationUri,
  );
  if (found.length !== 1 || !plain(found[0]!.params))
    throw new AgentCardError('attestation', 'The card carries no Better IAM attestation');
  const params = found[0]!.params as Record<string, unknown>;
  for (const field of [
    'issuer',
    'tenantId',
    'organization',
    'agentId',
    'agentName',
    'issuedAt',
    'expiresAt',
  ])
    if (typeof params[field] !== 'string')
      throw new AgentCardError('attestation', `The attestation has no ${field}`);
  if (params.sponsored !== true)
    throw new AgentCardError('attestation', 'The attestation does not state a sponsor');
  return params as unknown as AgentAttestation;
}

/** Fetched key sets by URL, shared by every verification that fetches keys with the same fetch. */
const jwksCache = new WeakMap<
  typeof fetch,
  Map<string, { jwks: CardJwks; until: number; fetchedAt: number }>
>();

/**
 * A JWKS from `url`, cached for `cacheSeconds`. With `fresh` (a signature named a key the cached set lacks), a set
 * older than 30 seconds is fetched again, so a newly activated key verifies without waiting out the cache.
 * @internal
 */
export async function fetchJwks(
  url: string,
  fetcher: typeof fetch,
  now: number,
  cacheSeconds: number,
  fresh = false,
): Promise<CardJwks> {
  let cache = jwksCache.get(fetcher);
  if (!cache) jwksCache.set(fetcher, (cache = new Map()));
  const cached = cache.get(url);
  if (cached && cached.until > now && !(fresh && now - cached.fetchedAt > 30_000))
    return cached.jwks;
  const text = await boundedText(
    await fetcher(url, {
      headers: { accept: 'application/jwk-set+json, application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    }),
    256 * 1024,
  );
  const parsed = JSON.parse(text) as unknown;
  if (!plain(parsed) || !Array.isArray(parsed.keys))
    throw new AgentCardError('untrusted-key', `${url} is not a JWKS`);
  const jwks = { keys: parsed.keys as CardJwk[] };
  if (cache.size > 64) cache.clear();
  cache.set(url, { jwks, until: now + cacheSeconds * 1000, fetchedAt: now });
  return jwks;
}

async function boundedText(response: Response, maxBytes: number): Promise<string> {
  if (!response.ok)
    throw new AgentCardError(
      'fetch',
      `${response.url || 'The server'} answered ${response.status}`,
    );
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new AgentCardError('fetch', `The response is larger than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Verifies that `card` was signed by a trusted Better IAM deployment and that its attestation is current: one of the
 * card's signatures verifies over the canonical card (RFC 8785, without `signatures`) with a trusted key, the card
 * carries exactly one attestation, it is neither expired nor from the future, and it matches `issuers`, `tenantId`
 * and `origin` when given. Throws `AgentCardError` otherwise.
 */
export async function verifyAgentCard(
  card: unknown,
  options: VerifyAgentCardOptions,
): Promise<VerifiedAgentCard> {
  if (!options.trustedIssuers && !options.keys && !options.trustedJwksUrls?.length)
    throw new TypeError('verifyAgentCard needs trustedIssuers, keys or trustedJwksUrls');
  if (!plain(card) || typeof card.url !== 'string' || typeof card.name !== 'string')
    throw new AgentCardError('malformed', 'Not an agent card');
  const signatures = card.signatures;
  if (!Array.isArray(signatures) || !signatures.length)
    throw new AgentCardError('unsigned', 'The card is not signed');
  const now = (options.now ?? Date.now)();
  const fetcher = options.fetch ?? globalThis.fetch;
  const cacheSeconds = options.jwksCacheSeconds ?? 300;
  // With trustedIssuers the keys are the named issuer's: read the (not yet verified) issuer first; the signature check
  // below then binds the card to that issuer's keys.
  let issuerKeys: string | CardJwks | undefined;
  if (options.trustedIssuers) {
    const claimed = attestationOf(card as AgentCard).issuer;
    if (!Object.hasOwn(options.trustedIssuers, claimed))
      throw new AgentCardError(
        'issuer',
        `The card was attested by ${claimed}, which is not trusted`,
      );
    issuerKeys = options.trustedIssuers[claimed];
  }
  const keysFor = async (
    kid: string,
    jku: string | undefined,
    fresh: boolean,
  ): Promise<CardJwks | undefined> => {
    if (issuerKeys !== undefined)
      return typeof issuerKeys === 'string'
        ? fetchJwks(issuerKeys, fetcher, now, cacheSeconds, fresh)
        : issuerKeys;
    if (options.keys)
      return typeof options.keys === 'function' ? options.keys(kid, jku) : options.keys;
    if (jku && options.trustedJwksUrls?.includes(jku))
      return fetchJwks(jku, fetcher, now, cacheSeconds, fresh);
    return undefined;
  };
  const { signatures: _signatures, ...unsigned } = card;
  let payload: string;
  try {
    payload = toBase64Url(new TextEncoder().encode(canonicalizeJson(unsigned)));
  } catch {
    throw new AgentCardError('malformed', 'The card is not plain JSON');
  }
  let verifiedKid: string | undefined;
  let sawTrustedKey = false;
  for (const entry of signatures.slice(0, 8) as unknown[]) {
    if (!plain(entry) || typeof entry.protected !== 'string' || typeof entry.signature !== 'string')
      continue;
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(new TextDecoder().decode(fromBase64Url(entry.protected))) as Record<
        string,
        unknown
      >;
    } catch {
      continue;
    }
    // Only plain detached card signatures (`typ` JOSE, never another JWT type signed with the same keys): no critical
    // extensions, no unencoded payloads.
    if (
      !plain(header) ||
      header.typ !== 'JOSE' ||
      header.crit !== undefined ||
      header.b64 !== undefined
    )
      continue;
    const alg = header.alg;
    const kid = header.kid;
    const jku = typeof header.jku === 'string' ? header.jku : undefined;
    if ((alg !== 'EdDSA' && alg !== 'ES256') || typeof kid !== 'string') continue;
    const pick = (jwks: CardJwks | undefined) =>
      jwks?.keys.find(
        (key) => key.kid === kid && (key.alg === undefined || key.alg === alg) && key.use !== 'enc',
      );
    let jwk: CardJwk | undefined;
    try {
      // A key the (cached) set lacks may have been activated since: look once more with a fresh set.
      jwk = pick(await keysFor(kid, jku, false)) ?? pick(await keysFor(kid, jku, true));
    } catch (error) {
      if (error instanceof AgentCardError && error.reason === 'fetch') throw error;
      jwk = undefined;
    }
    if (!jwk) continue;
    sawTrustedKey = true;
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = fromBase64Url(entry.signature);
    } catch {
      continue;
    }
    const signingInput = new TextEncoder().encode(`${entry.protected}.${payload}`);
    if (await verifySignature(jwk, alg, signingInput, signature)) {
      verifiedKid = kid;
      break;
    }
  }
  if (!verifiedKid)
    throw sawTrustedKey
      ? new AgentCardError('signature', 'The card signature does not verify')
      : new AgentCardError('untrusted-key', 'The card is not signed with a trusted key');
  const verified = card as AgentCard;
  const attestation = attestationOf(verified);
  const tolerance = (options.clockToleranceSeconds ?? 60) * 1000;
  const issuedAt = Date.parse(attestation.issuedAt);
  const expiresAt = Date.parse(attestation.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt))
    throw new AgentCardError('attestation', 'The attestation times are invalid');
  if (issuedAt > now + tolerance)
    throw new AgentCardError('attestation', 'The attestation is not valid yet');
  if (expiresAt <= now - tolerance)
    throw new AgentCardError('expired', 'The attestation has expired');
  if (options.issuers && !options.issuers.includes(attestation.issuer))
    throw new AgentCardError('issuer', `The card was attested by ${attestation.issuer}`);
  if (options.tenantId !== undefined && attestation.tenantId !== options.tenantId)
    throw new AgentCardError('tenant', 'The agent belongs to another organization');
  if (options.origin !== undefined) {
    let origin: string | undefined;
    try {
      origin = new URL(verified.url).origin;
    } catch {
      origin = undefined;
    }
    if (origin !== new URL(options.origin).origin)
      throw new AgentCardError('endpoint', 'The card describes an agent on another origin');
  }
  return { card: verified, attestation, kid: verifiedKid };
}

export interface DiscoverAgentOptions extends VerifyAgentCardOptions {
  /** Largest accepted card in bytes (default 256 KiB). */
  maxBytes?: number;
  /** Timeout of the card request in milliseconds (default 5000). */
  timeoutMs?: number;
}

/**
 * Fetches a remote agent's card (`url` itself when it ends in `.json`, otherwise `/.well-known/agent-card.json` on its
 * origin) and verifies it with `verifyAgentCard`, requiring the card's `url` to be on the origin it was fetched from.
 * Call it only with agent addresses you chose: it makes an outbound request.
 */
export async function discoverAgent(
  url: string,
  options: DiscoverAgentOptions,
): Promise<VerifiedAgentCard> {
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.protocol !== 'http:')
    throw new AgentCardError('fetch', 'Agent cards are fetched over http(s)');
  const location = target.pathname.endsWith('.json')
    ? target
    : new URL('/.well-known/agent-card.json', target.origin);
  const fetcher = options.fetch ?? globalThis.fetch;
  let text: string;
  try {
    const response = await fetcher(location, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
    });
    text = await boundedText(response, options.maxBytes ?? 256 * 1024);
  } catch (error) {
    if (error instanceof AgentCardError) throw error;
    throw new AgentCardError('fetch', `Could not fetch ${location.href}`);
  }
  let card: unknown;
  try {
    card = JSON.parse(text);
  } catch {
    throw new AgentCardError('malformed', `${location.href} is not JSON`);
  }
  return verifyAgentCard(card, { ...options, origin: options.origin ?? location.origin });
}

export interface CardAttestorOptions {
  /** The card to have attested (without signatures): an object, or a function building it. */
  card: AgentCard | (() => AgentCard | Promise<AgentCard>);
  /**
   * Signs a card through Better IAM, for example
   * `(card) => iam.api.agents.signCard({ token: agentKey }, { tenantId, agentId, card })`.
   */
  sign(card: AgentCard): Promise<{ card: Record<string, unknown>; expiresAt: number }>;
  /** Re-sign once less than this share of the attestation's lifetime is left (default 0.2). */
  refreshShare?: number;
  now?: () => number;
}

/**
 * Keeps an agent's own card attested: returns a function that yields the signed card, signing on first use and again
 * when the attestation nears its end. Concurrent calls share one signing request; when re-signing fails while the
 * previous card is still valid, that card is returned.
 */
export function createCardAttestor(options: CardAttestorOptions): () => Promise<AgentCard> {
  const now = options.now ?? Date.now;
  const share = options.refreshShare ?? 0.2;
  let current: { card: AgentCard; signedAt: number; expiresAt: number } | undefined;
  let pending: Promise<AgentCard> | undefined;
  const sign = async (): Promise<AgentCard> => {
    // Yield first, so the work (and its settling) always happens after `pending` is set.
    await null;
    try {
      const base = typeof options.card === 'function' ? await options.card() : options.card;
      const signedAt = now();
      const signed = await options.sign(base);
      current = { card: signed.card as AgentCard, signedAt, expiresAt: signed.expiresAt };
      return current.card;
    } catch (error) {
      if (current && current.expiresAt > now()) return current.card;
      throw error;
    }
  };
  const refresh = (): Promise<AgentCard> => {
    if (pending) return pending;
    const run = sign();
    pending = run;
    void run.then(
      () => {
        if (pending === run) pending = undefined;
      },
      () => {
        if (pending === run) pending = undefined;
      },
    );
    return run;
  };
  return async () => {
    if (!current) return refresh();
    const left = current.expiresAt - now();
    if (left <= (current.expiresAt - current.signedAt) * share) return refresh();
    return current.card;
  };
}
