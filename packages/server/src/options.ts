import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  IamError,
  type AuditEvent,
  type AuditSessionContext,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type HierarchyConfig,
  type IamPlugin,
  type IamStore,
  type Json,
  type PermissionsConfig,
  type ResourceRef,
  type SessionClientInfo,
  type TenantAuthPolicy,
  type TenantLimits,
} from '@better-iam/core';
import type { AuthOptions } from '@better-iam/auth';
import type { DomainOptions } from './api/domains.js';
import {
  resolveHostConfig,
  resolveRegionConfig,
  type HostOptions,
  type RegionOptions,
  type ResolvedHostConfig,
  type ResolvedRegionConfig,
} from './hosts.js';
import type { ObservabilityOptions } from './observe.js';
import { tenantAuthPolicy, tenantLimits } from './tenant-policy.js';
import { integer, text } from './validation.js';
import type { JWK } from 'jose';
import { webIdentityIssuer } from './web-identity.js';

/** The JSON body delivered to a webhook endpoint. */
export interface WebhookEvent {
  id: string;
  type: string;
  tenantId: string;
  actorId: string;
  originalActorId?: string;
  /** Set when an administrator acted through an impersonation session; `actorId` is the member. */
  impersonatorId?: string;
  resourceId: string;
  outcome: 'allow' | 'deny';
  rootOverride?: boolean;
  timestamp: number;
  metadata?: Record<string, Json>;
  /**
   * The session the actor used (API key, user, role or session token), with the role, trust and session names behind
   * a temporary credential; absent for events recorded without a principal.
   */
  sessionContext?: AuditSessionContext;
  /** Position and hash of the event in the tenant's audit chain, for consumers that reconcile against exports. */
  sequence?: number;
  hash?: string;
}
/** A signed delivery handed to `events.deliverWebhook` when the default HTTP transport is replaced. */
export interface WebhookDelivery {
  id: string;
  tenantId: string;
  webhookId: string;
  url: string;
  event: string;
  body: string;
  headers: Record<string, string>;
}
export interface EventOptions {
  /** Called after commit for every audit event, from the dispatcher worker; at-least-once. */
  onEvent?(event: AuditEvent): Promise<void> | void;
  /** Replaces the built-in HTTPS POST transport; signature headers are already computed. */
  deliverWebhook?(delivery: WebhookDelivery): Promise<void>;
  /** Timeout for the built-in transport (default 10 seconds). */
  webhookTimeoutMs?: number;
}
export interface AccessRequestOptions {
  /** How long a pending request stays open (default 7 days). */
  lifetimeMs?: number;
  /** Longest temporary grant a request may ask for (default 90 days). */
  maxDurationSeconds?: number;
}
export interface HttpOptions {
  /**
   * Derives the client details recorded on sessions issued by a request (IP behind a trusted proxy, user agent, a
   * device label). The default records the User-Agent header only; never trust X-Forwarded-For without a proxy you control.
   */
  clientInfo?(request: Request): SessionClientInfo | undefined;
  /**
   * `SameSite` of the session and device cookies: `lax` (default; the cookie also rides top-level navigations
   * from other sites, such as a link in an email) or `strict` (first-party requests only).
   */
  cookieSameSite?: 'lax' | 'strict';
  /**
   * Whether session cookies outlive the browser by default. `true` (default) sets `Max-Age` to the session's remaining
   * lifetime; `false` issues browser-session cookies that disappear when the browser closes while the server session
   * keeps its normal lifetime. A request that issues a session overrides the default with the
   * `X-Better-IAM-Persistent: 1|0` header (the console's "keep me signed in" checkbox).
   */
  persistentCookies?: boolean;
}
export interface ProtocolMount {
  handle?(request: Request): Promise<Response | undefined>;
  nodeHandler?(req: IncomingMessage, res: ServerResponse): Promise<boolean | void> | boolean | void;
}
export interface AuthorizationRequest extends CredentialInput {
  tenantId: string;
  action: string;
  resource: { type: string; id: string };
}
export interface AuthorizationCheck {
  action: string;
  resource: { type: string; id: string };
}
export interface BatchAuthorizationRequest extends CredentialInput {
  tenantId: string;
  checks: AuthorizationCheck[];
}
/** Reverse query: which registered resources of a managed type may the caller perform an action on. */
export interface AccessibleResourcesRequest extends CredentialInput {
  tenantId: string;
  action: string;
  type: string;
  limit?: number;
  offset?: number;
}
export type ResolvedResource = ResourceRef & { attributes?: Record<string, unknown> };

/**
 * Signing keys for session JWTs (`format: 'jwt'` role sessions and session tokens). They are separate from
 * `secret`, so rotating the deployment secret never affects them, and they are never shared with the OAuth provider.
 */
export interface SessionTokenSigningOptions {
  /**
   * Private JWKs, 1 to 10: `kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA'` or `kty: 'EC', crv: 'P-256', alg: 'ES256'`,
   * each with a unique `kid` (/^[A-Za-z0-9._-]{1,64}$/), `use` absent or `'sig'`, `key_ops` absent or including `'sign'`.
   */
  signingKeys: JWK[];
  /** The `kid` new tokens are signed with (default: the first signing key). */
  activeKeyId?: string;
  /** Public-only retired keys (0 to 10) that still verify but never sign; the rotation window. */
  verificationKeys?: JWK[];
  /** The `iss` claim (default `${baseURL.origin}${basePath}`). */
  issuer?: string;
  /** Audiences a token may be issued for; the issuer is always included. */
  audiences?: string[];
  /** Longest JWT lifetime in seconds, 300..43200 (default 3600). */
  maxLifetimeSeconds?: number;
}

/** AssumeRoleWithWebIdentity: exchanging external OIDC tokens (CI, Kubernetes, cloud workloads) for role sessions. */
export interface StsWebIdentityOptions {
  /** Off by default. */
  enabled?: boolean;
  /** Pins the issuers any tenant may register as an OIDC provider (at most 100 https issuers). */
  allowedIssuers?: string[];
  /** How long fetched provider keys are cached, 60..3600 seconds (default 600). */
  jwksCacheSeconds?: number;
  /** Timeout of each discovery or JWKS fetch, 500..10000 ms (default 5000). */
  fetchTimeoutMs?: number;
  /** Largest accepted discovery or JWKS response, 1024..1048576 bytes (default 65536). */
  maxJwksBytes?: number;
  /** Exchanges per trust per rate-limit window, 1..100000 (default 600). */
  maxExchangesPerWindow?: number;
  /** Live role sessions per web-identity trust, 1..100000 (default 1000). */
  maxSessionsPerTrust?: number;
  /** Lets discovery and JWKS fetches reach private and reserved addresses. Development and tests only. */
  allowPrivateNetworks?: boolean;
  /** Accepts `http://` issuers and key URLs on loopback hosts. Development and tests only. */
  allowInsecureLocalhost?: boolean;
  /**
   * Replaces the built-in fetch (which refuses private addresses, redirects, oversized and non-JSON responses). The
   * host is responsible for the safety of its transport.
   */
  fetchJson?: (url: URL) => Promise<unknown>;
}

/** Temporary credentials (STS): role sessions, session tokens, JWT format and web-identity federation. */
export interface StsOptions {
  /** Ceiling for role session durations, 900..43200 seconds (default 3600); trusts can only lower it. */
  maxRoleSessionSeconds?: number;
  /** Ceiling for session token durations, 900..129600 seconds (default 43200). */
  maxSessionTokenSeconds?: number;
  /** Live session tokens per identity, 1..1000 (default 50). */
  maxSessionTokensPerIdentity?: number;
  /** Enables `format: 'jwt'` and the JWKS route. */
  jwt?: SessionTokenSigningOptions;
  webIdentity?: StsWebIdentityOptions;
}

/** Validated STS settings with defaults applied. `jwt` is validated by the session token signer. */
export interface ResolvedStsConfig {
  maxRoleSessionSeconds: number;
  maxSessionTokenSeconds: number;
  maxSessionTokensPerIdentity: number;
  webIdentity: {
    enabled: boolean;
    allowedIssuers?: readonly string[];
    jwksCacheSeconds: number;
    fetchTimeoutMs: number;
    maxJwksBytes: number;
    maxExchangesPerWindow: number;
    maxSessionsPerTrust: number;
    allowPrivateNetworks: boolean;
    allowInsecureLocalhost: boolean;
  };
}

export interface BetterIamOptions {
  database: IamStore;
  secret: string;
  /**
   * Deployment secrets being rotated out (at most five). Everything they sealed or signed keeps
   * working, while new values use `secret`; `rotateSecrets()` re-seals stored values, after which
   * they can be removed. See the deployment guide.
   */
  previousSecrets?: string[];
  baseURL: string;
  basePath?: string;
  trustedOrigins?: string[];
  authentication?: Omit<
    AuthOptions,
    'store' | 'secret' | 'previousSecrets' | 'baseURL' | 'trustedOrigins'
  >;
  hierarchy?: HierarchyConfig;
  permissions?: PermissionsConfig;
  onboarding?: { mode?: 'invitation' | 'linked'; invitationLifetimeMs?: number };
  plugins?: IamPlugin[];
  events?: EventOptions;
  /**
   * Continuous audit archiving (`iam.archiveAudit()`): where verified batches of each tenant's
   * audit chain go. While it is set, `pruneAudit` only deletes events already archived.
   */
  auditArchive?: import('./audit-archive.js').AuditArchiveOptions;
  accessRequests?: AccessRequestOptions;
  /** Timing and outcome of every operation, authorization query, authentication call, and HTTP request. */
  observability?: ObservabilityOptions;
  /**
   * Records which actions each identity is actually allowed to use (buffered, written in batches) so
   * `roleMining.usage` / `roleMining.rightSize` can point out unused bindings and never-used grants. Off by default.
   */
  accessUsage?: boolean | import('./usage.js').AccessUsageOptions;
  /**
   * Inference access control for AI models: the `model` resource type and `inference:invoke` action, the `inference`
   * API group (providers with sealed keys, models, budgets, usage) and `iam.inference` (checks, metering and the
   * gateway). Off by default.
   */
  inference?: boolean | import('./inference.js').InferenceOptions;
  /**
   * IAM-attested A2A agent cards: the keys `agents.signCard` signs agents' Agent2Agent cards with, and where their
   * public half is published (`iam.a2a.jwks()`). Off by default.
   */
  a2a?: import('./a2a.js').A2aOptions;
  /**
   * Billing and spend tracking settings (`billing` API group, `iam.billing`): currency, the time zone billing months
   * follow, usage retention, how team spend is attributed, payment terms. Billing is always available; these tune it.
   */
  billing?: import('./billing.js').BillingOptions;
  http?: HttpOptions;
  /** Plan limits and authentication policy applied to every tenant created through `tenants.create`. */
  tenantDefaults?: { limits?: TenantLimits; authPolicy?: TenantAuthPolicy };
  /** Verified email domains and home-realm discovery (`domains` API group). */
  domains?: DomainOptions;
  /**
   * Organization sign-in addresses: subdomains built from each organization's alias (`acme.signin.example.com`),
   * optionally per region, and verified custom hostnames (`login.acme.com`). Requests on an organization's address
   * are pinned to it.
   */
  hosts?: HostOptions;
  /** Multi-region deployments: this deployment's region and where every region's deployment answers. */
  regions?: RegionOptions;
  /** Required for product resource types; resolves ownership and attributes from trusted storage. */
  resolveResource?(
    reference: ResourceRef,
  ): Promise<ResourceRef & { attributes?: Record<string, unknown> }>;
  resolveContext?(principal: AuthenticatedPrincipal): Promise<Record<string, unknown>>;
  protocols?: ProtocolMount[];
  /** Temporary credentials: duration ceilings, session JWT signing keys and web-identity federation. */
  sts?: StsOptions;
}

/** Validated, defaulted configuration derived once from the options. */
export interface ServerConfig {
  baseURL: URL;
  basePath: string;
  trustedOrigins: Set<string>;
  hierarchy: HierarchyConfig;
  maxDepth: number;
  tenantDefined: boolean;
  strictResourceTypes: boolean;
  linkedOnboarding: boolean;
  invitationLifetimeMs: number;
  accessRequestLifetimeMs: number;
  accessRequestMaxDurationSeconds: number;
  webhookTimeoutMs: number;
  tenantDefaults: { limits?: TenantLimits; authPolicy?: TenantAuthPolicy };
  sts: ResolvedStsConfig;
  /** Organization sign-in addresses (`hosts` option), compiled. */
  hosts: ResolvedHostConfig;
  /** Region settings (`regions` option); undefined for single-region deployments. */
  regions?: ResolvedRegionConfig;
}

const defaultHierarchy: HierarchyConfig = {
  types: {
    root: { allowedChildren: ['organization'] },
    organization: { allowedChildren: ['project'] },
    project: { allowedChildren: [] },
  },
  maxDepth: 8,
};

export function resolveConfig(options: BetterIamOptions): ServerConfig {
  if (!options.database) throw new IamError('INVALID_CONFIG', 'database is required');
  const baseURL = new URL(options.baseURL);
  if (
    baseURL.protocol !== 'https:' &&
    !['localhost', '127.0.0.1', '[::1]'].includes(baseURL.hostname)
  )
    throw new IamError('INVALID_CONFIG', 'HTTPS is required outside localhost');
  const basePath = options.basePath ?? '/api/iam';
  if (!/^\/[\w/-]+$/.test(basePath) || basePath.endsWith('/'))
    throw new IamError('INVALID_CONFIG', 'Invalid basePath');
  const hierarchy = options.hierarchy ?? defaultHierarchy;
  const maxDepth = hierarchy.maxDepth ?? 8;
  integer(maxDepth, 'maxDepth', 1, 100);
  if (!hierarchy.types.root) throw new IamError('INVALID_CONFIG', 'Hierarchy must define root');
  for (const [name, type] of Object.entries(hierarchy.types)) {
    text(name, 'tenant type');
    for (const child of type.allowedChildren)
      if (!hierarchy.types[child] || child === 'root')
        throw new IamError('INVALID_CONFIG', 'Invalid allowed child type');
  }
  const tenantDefaults: ServerConfig['tenantDefaults'] = {};
  try {
    if (options.tenantDefaults?.limits !== undefined)
      tenantDefaults.limits = tenantLimits(options.tenantDefaults.limits);
    if (options.tenantDefaults?.authPolicy !== undefined)
      tenantDefaults.authPolicy = tenantAuthPolicy(options.tenantDefaults.authPolicy);
  } catch (error) {
    throw new IamError('INVALID_CONFIG', `tenantDefaults: ${(error as Error).message}`);
  }
  const regions = resolveRegionConfig(options.regions);
  const hosts = resolveHostConfig(options.hosts, {
    baseURL,
    ...(regions ? { regions } : {}),
    ...(options.authentication?.passkeys?.rpID
      ? { passkeyRpId: options.authentication.passkeys.rpID }
      : {}),
  });
  return {
    hosts,
    ...(regions ? { regions } : {}),
    tenantDefaults,
    baseURL,
    basePath,
    trustedOrigins: new Set([baseURL.origin, ...(options.trustedOrigins ?? [])]),
    hierarchy,
    maxDepth,
    tenantDefined: options.permissions?.mode === 'tenant-defined',
    strictResourceTypes: options.permissions?.resourceTypes !== undefined,
    linkedOnboarding: options.onboarding?.mode === 'linked',
    invitationLifetimeMs: options.onboarding?.invitationLifetimeMs ?? 86400000,
    accessRequestLifetimeMs: integer(
      options.accessRequests?.lifetimeMs ?? 7 * 86400000,
      'accessRequests.lifetimeMs',
      60_000,
      365 * 86400000,
    ),
    accessRequestMaxDurationSeconds: integer(
      options.accessRequests?.maxDurationSeconds ?? 90 * 86400,
      'accessRequests.maxDurationSeconds',
      60,
      10 * 365 * 86400,
    ),
    webhookTimeoutMs: integer(
      options.events?.webhookTimeoutMs ?? 10_000,
      'events.webhookTimeoutMs',
      1_000,
      120_000,
    ),
    sts: resolveStsConfig(options.sts, options.sts?.jwt?.issuer ?? `${baseURL.origin}${basePath}`),
  };
}

/** Validates `options.sts` (except `jwt`, which the session token signer checks) and applies the defaults. */
function resolveStsConfig(options: StsOptions | undefined, selfIssuer: string): ResolvedStsConfig {
  const invalid = (field: string, detail: string): never => {
    throw new IamError('INVALID_CONFIG', `sts.${field} ${detail}`);
  };
  if (options !== undefined && (options === null || typeof options !== 'object'))
    invalid('options', 'must be an object');
  const number = (value: unknown, fallback: number, field: string, min: number, max: number) => {
    try {
      return integer(value ?? fallback, field, min, max);
    } catch {
      return invalid(field, `must be an integer from ${min} to ${max}`);
    }
  };
  const flag = (value: unknown, field: string) => {
    if (value !== undefined && typeof value !== 'boolean') invalid(field, 'must be a boolean');
    return value === true;
  };
  const web = options?.webIdentity;
  if (web !== undefined && (web === null || typeof web !== 'object'))
    invalid('webIdentity', 'must be an object');
  if (web?.fetchJson !== undefined && typeof web.fetchJson !== 'function')
    invalid('webIdentity.fetchJson', 'must be a function');
  const allowInsecureLocalhost = flag(
    web?.allowInsecureLocalhost,
    'webIdentity.allowInsecureLocalhost',
  );
  let allowedIssuers: readonly string[] | undefined;
  if (web?.allowedIssuers !== undefined) {
    if (!Array.isArray(web.allowedIssuers) || web.allowedIssuers.length > 100)
      invalid('webIdentity.allowedIssuers', 'must be an array of at most 100 issuers');
    allowedIssuers = Object.freeze([
      ...new Set(
        web.allowedIssuers.map((issuer) => {
          try {
            return webIdentityIssuer(issuer, { allowInsecureLocalhost, selfIssuer });
          } catch (error) {
            return invalid(
              'webIdentity.allowedIssuers',
              `contains an invalid issuer: ${(error as Error).message}`,
            );
          }
        }),
      ),
    ]);
  }
  return {
    maxRoleSessionSeconds: number(
      options?.maxRoleSessionSeconds,
      3600,
      'maxRoleSessionSeconds',
      900,
      43200,
    ),
    maxSessionTokenSeconds: number(
      options?.maxSessionTokenSeconds,
      43200,
      'maxSessionTokenSeconds',
      900,
      129600,
    ),
    maxSessionTokensPerIdentity: number(
      options?.maxSessionTokensPerIdentity,
      50,
      'maxSessionTokensPerIdentity',
      1,
      1000,
    ),
    webIdentity: {
      enabled: flag(web?.enabled, 'webIdentity.enabled'),
      ...(allowedIssuers ? { allowedIssuers } : {}),
      jwksCacheSeconds: number(
        web?.jwksCacheSeconds,
        600,
        'webIdentity.jwksCacheSeconds',
        60,
        3600,
      ),
      fetchTimeoutMs: number(web?.fetchTimeoutMs, 5000, 'webIdentity.fetchTimeoutMs', 500, 10_000),
      maxJwksBytes: number(web?.maxJwksBytes, 65536, 'webIdentity.maxJwksBytes', 1024, 1_048_576),
      maxExchangesPerWindow: number(
        web?.maxExchangesPerWindow,
        600,
        'webIdentity.maxExchangesPerWindow',
        1,
        100_000,
      ),
      maxSessionsPerTrust: number(
        web?.maxSessionsPerTrust,
        1000,
        'webIdentity.maxSessionsPerTrust',
        1,
        100_000,
      ),
      allowPrivateNetworks: flag(web?.allowPrivateNetworks, 'webIdentity.allowPrivateNetworks'),
      allowInsecureLocalhost,
    },
  };
}
