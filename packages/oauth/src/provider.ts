import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createLocalJWKSet, jwtVerify } from 'jose';
import Provider, {
  errors,
  type ClientMetadata,
  type Configuration,
  type JWKS,
} from 'oidc-provider';
import {
  IamError,
  appendAuditEvent,
  tenantTreeActive,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type ResourceRef,
  type Session,
  type StoredRecord,
} from '@better-iam/core';
import {
  cipher,
  createProviderAdapter,
  encryptionKey,
  hash,
  type Artifact,
  type ClientRow,
  type GrantSession,
} from './adapter.js';

export { createProviderAdapter } from './adapter.js';

/** A protected API that clients address with an RFC 8707 `resource` indicator. */
export interface OAuthResourceServer {
  /** Scopes this API understands; requested scopes outside this set are dropped from its access tokens. */
  scopes: string[];
  /** Access token `aud`; defaults to the resource indicator. */
  audience?: string;
  /** Access token lifetime in seconds (default 900). */
  accessTokenTtl?: number;
  /** `jwt` (default) lets the API verify tokens offline with `createAccessTokenVerifier`; `opaque` requires introspection. */
  accessTokenFormat?: 'jwt' | 'opaque';
}

export interface OAuthProviderConfig {
  store: IamStore;
  issuer: string;
  jwks: JWKS;
  cookieKeys: string[];
  /** Base64-encoded 32-byte key, separate from signing keys. Encrypts provider artifacts at rest. */
  encryptionKey: string;
  authenticate(credential: CredentialInput): Promise<AuthenticatedPrincipal>;
  /** Host validation applies custom idle limits, email verification, and current MFA policy. */
  validateSession?(sessionId: string): Promise<unknown>;
  authorize(credential: CredentialInput, action: string, resource: ResourceRef): Promise<unknown>;
  interactionUrl(uid: string): string;
  /** Render application-owned pages around the provider's CSRF-protected form markup. */
  renderDevicePage(input: {
    kind: 'input' | 'confirm' | 'success';
    form: string;
    userCode?: string;
    clientName?: string;
  }): string | Promise<string>;
  renderLogoutPage(input: { form: string }): string | Promise<string>;
  trustedOrigins: string[];
  /** Product-defined OAuth scopes; scopes are not IAM permission grants. */
  scopes?: string[];
  /**
   * Protected APIs keyed by resource indicator (an absolute URI). A client registered with `resources` may request
   * audience-restricted access tokens for them with the `resource` parameter.
   */
  resourceServers?: Record<string, OAuthResourceServer>;
  /** Reject authorization requests that were not pushed first (RFC 9126) for every client. */
  requirePushedAuthorizationRequests?: boolean;
  /** Base64-encoded 32-byte secret enabling server-provided DPoP nonces; identical on every instance. */
  dpopNonceSecret?: string;
  /**
   * Extra policy for token exchange (RFC 8693) after the built-in checks; return false to refuse with
   * `access_denied`. Without it, any client registered for the grant may exchange for its own resources and scopes.
   */
  authorizeTokenExchange?(request: TokenExchangeRequest): boolean | Promise<boolean>;
  /**
   * Dynamic client registration (RFC 7591) at the discovered `registration_endpoint`. Registrations present a
   * tenant-scoped token from `createRegistrationToken`, or — for clients such as MCP hosts that register without
   * one — pass the `anonymous` hook, which maps the request to a tenant and limits (or declines it).
   */
  registration?: {
    anonymous?(request: {
      headers: Record<string, string | string[] | undefined>;
      ip?: string;
    }): RegistrationPolicy | undefined | Promise<RegistrationPolicy | undefined>;
  };
  trustProxy?: boolean;
  allowInsecureLocalhost?: boolean;
}

/** What dynamically registered clients of one tenant may be. */
export interface RegistrationPolicy {
  tenantId: string;
  /** Scopes the client may use (default `openid profile email offline_access`); a registration asking for more fails. */
  scopes?: string[];
  /** Resource indicators the client may request tokens for. */
  resources?: string[];
  /** Allow confidential clients (a client secret); by default only public PKCE clients register. */
  allowConfidential?: boolean;
  /** Anonymous registrations only: at most this many clients per tenant (default 100). */
  maxClients?: number;
}

/** A tenant-scoped initial access token for dynamic client registration. The token itself is shown once. */
export interface RegistrationTokenSummary {
  id: string;
  tenantId: string;
  name: string;
  scopes: string[];
  resources: string[];
  allowConfidential: boolean;
  maxClients: number;
  used: number;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}

/** A token exchange the provider is about to perform, for `authorizeTokenExchange`. */
export interface TokenExchangeRequest {
  tenantId: string;
  /** The client exchanging the token; it becomes the `act` (actor) of the issued token. */
  clientId: string;
  /** The account the subject token represents. */
  identityId: string;
  /** The client the subject token was issued to. */
  subjectClientId: string;
  subjectScopes: string[];
  resource: string;
  scopes: string[];
}

export type OAuthGrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  | 'urn:ietf:params:oauth:grant-type:device_code'
  | 'urn:ietf:params:oauth:grant-type:token-exchange';

/** Client settings shared by registration and updates. */
export interface OAuthClientSettings {
  name: string;
  redirectUris: string[];
  grantTypes?: OAuthGrantType[];
  scopes?: string[];
  postLogoutRedirectUris?: string[];
  /** Resource indicators from `resourceServers` this client may request access tokens for. */
  resources?: string[];
  /** Only issue sender-constrained (DPoP, RFC 9449) access tokens to this client. */
  requireDpop?: boolean;
  /** Require pushed authorization requests (RFC 9126) from this client. */
  requirePushedAuthorization?: boolean;
  /** Receives OpenID back-channel logout tokens when the account's IAM session ends (`logoutEndedSessions`). */
  backchannelLogoutUri?: string;
  /** Public signing keys of a `private_key_jwt` client; replace them to rotate keys. */
  jwks?: JWKS;
  /** Or the HTTPS URL the provider fetches those keys from. */
  jwksUri?: string;
  /** Access token lifetime in seconds (60 to 86400); a resource server's shorter lifetime still applies. */
  accessTokenTtl?: number;
  /** Refresh token lifetime in seconds (300 to 30 days), renewed on each rotation within the consent's lifetime. */
  refreshTokenTtl?: number;
  /** Consent-screen branding (HTTPS URLs): the client's logo, home page, privacy policy, and terms of service. */
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  /**
   * A first-party application of the deployment. `interactionDetails` reports it so the host may approve consent
   * without asking; the provider itself never skips the interaction.
   */
  firstParty?: boolean;
}

/** How a confidential client authenticates at the token, introspection, and revocation endpoints. */
export type OAuthClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'private_key_jwt';

export interface RegisterOAuthClient extends OAuthClientSettings {
  tenantId: string;
  clientId: string;
  public?: boolean;
  /** Confidential clients only; defaults to `client_secret_basic`. `private_key_jwt` needs `jwks` or `jwksUri`. */
  tokenEndpointAuthMethod?: OAuthClientAuthMethod;
  serviceAccountId?: string;
}

export interface UpdateOAuthClient
  extends Partial<
    Omit<
      OAuthClientSettings,
      | 'backchannelLogoutUri'
      | 'accessTokenTtl'
      | 'refreshTokenTtl'
      | 'logoUri'
      | 'clientUri'
      | 'policyUri'
      | 'tosUri'
    >
  > {
  tenantId: string;
  clientId: string;
  /** `null` removes the back-channel logout URI. */
  backchannelLogoutUri?: string | null;
  /** `null` restores the provider default. */
  accessTokenTtl?: number | null;
  refreshTokenTtl?: number | null;
  /** `null` removes a branding URL. */
  logoUri?: string | null;
  clientUri?: string | null;
  policyUri?: string | null;
  tosUri?: string | null;
}

/** A registered client as administrators see it. The secret is never returned after registration or rotation. */
export interface OAuthClientSummary {
  clientId: string;
  tenantId: string;
  name: string;
  public: boolean;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: OAuthGrantType[];
  scopes: string[];
  resources: string[];
  requireDpop: boolean;
  requirePushedAuthorization: boolean;
  tokenEndpointAuthMethod: OAuthClientAuthMethod | 'none';
  backchannelLogoutUri?: string;
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
  jwksUri?: string;
  /** Key IDs of inline `jwks` (keys without `kid` are listed by their key type). */
  keyIds?: string[];
  serviceAccountId?: string;
  revoked: boolean;
  createdAt?: number;
  updatedAt?: number;
  secretRotatedAt?: number;
  /** Dynamically registered clients: the registration token ID, or `anonymous`. */
  registeredVia?: string;
  logoUri?: string;
  clientUri?: string;
  policyUri?: string;
  tosUri?: string;
  firstParty: boolean;
}

/** A consent an account gave a client ("connected app"). `id` is an opaque reference, not the grant identifier. */
export interface OAuthGrantSummary {
  id: string;
  tenantId: string;
  identityId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  claims: string[];
  resources: Record<string, string[]>;
  createdAt: number;
  expiresAt: number;
}

const grantTypesSupported: OAuthGrantType[] = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:device_code',
  'urn:ietf:params:oauth:grant-type:token-exchange',
];
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const loopback = ['localhost', '127.0.0.1', '[::1]'];
const defaultRegistrationScopes = ['openid', 'profile', 'email', 'offline_access'];

/** What the registration gate decided for one `POST /reg`. */
interface RegistrationContext {
  tenantId: string;
  scopes: string[];
  resources: string[];
  allowConfidential: boolean;
  maxClients: number;
  /** The registration token's record ID; absent for anonymous registrations. */
  tokenId?: string;
  actorId: string;
}
interface RegistrationTokenRecord extends StoredRecord {
  name: string;
  scopes: string[];
  resources: string[];
  allowConfidential: boolean;
  maxClients: number;
  used: number;
  createdBy: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}
const registrationContext = new AsyncLocalStorage<RegistrationContext>();
const scopeName = /^[a-zA-Z0-9:_.-]{1,128}$/;

/**
 * OAuth 2.0 / OpenID Connect authorization server built on oidc-provider: persistent encrypted artifacts, PKCE-only
 * authorization code, rotating refresh tokens, client credentials, device authorization, pushed authorization
 * requests, DPoP sender-constrained tokens, resource indicators with JWT access tokens, and IAM-bound consent.
 */
export function createOAuthProvider(config: OAuthProviderConfig) {
  const issuer = new URL(config.issuer);
  const secureOrLocal = (url: URL) =>
    url.protocol === 'https:' ||
    (config.allowInsecureLocalhost && url.protocol === 'http:' && loopback.includes(url.hostname));
  if (issuer.search || issuer.hash || issuer.username || issuer.password || !secureOrLocal(issuer))
    throw new IamError('configuration', 'OAuth issuer must use HTTPS.');
  if (
    !config.jwks?.keys?.length ||
    !config.cookieKeys?.length ||
    config.cookieKeys.some((value) => value.length < 32) ||
    !config.interactionUrl ||
    !config.renderDevicePage ||
    !config.renderLogoutPage ||
    !config.trustedOrigins.length
  )
    throw new IamError(
      'configuration',
      'OAuth provider signing keys, cookie keys, interaction callbacks, and trusted origins are required.',
    );
  const crypt = cipher(encryptionKey(config.encryptionKey));
  const resourceServers = new Map(Object.entries(config.resourceServers ?? {}));
  for (const [indicator, server] of resourceServers) {
    let parsed: URL;
    try {
      parsed = new URL(indicator);
    } catch {
      throw new IamError('configuration', 'Resource indicators must be absolute URIs.');
    }
    if (parsed.hash || parsed.search)
      throw new IamError(
        'configuration',
        'Resource indicators cannot carry a query or fragment (RFC 8707).',
      );
    if (
      !Array.isArray(server.scopes) ||
      !server.scopes.length ||
      server.scopes.some((scope) => typeof scope !== 'string' || !scopeName.test(scope)) ||
      (server.accessTokenTtl !== undefined &&
        (!Number.isSafeInteger(server.accessTokenTtl) || server.accessTokenTtl <= 0)) ||
      (server.accessTokenFormat !== undefined &&
        !['jwt', 'opaque'].includes(server.accessTokenFormat))
    )
      throw new IamError(
        'configuration',
        'Resource servers need scope identifiers, a positive integer TTL, and a jwt or opaque format.',
      );
  }
  const supportedScopes = [
    ...new Set([
      'openid',
      'email',
      'profile',
      'offline_access',
      'iam',
      ...(config.scopes ?? []),
      ...[...resourceServers.values()].flatMap((server) => server.scopes),
    ]),
  ];
  if (supportedScopes.some((scope) => !scopeName.test(scope)))
    throw new IamError('configuration', 'OAuth scopes must be nonempty identifiers.');
  let dpopNonceSecret: Buffer | undefined;
  if (config.dpopNonceSecret !== undefined) {
    dpopNonceSecret = Buffer.from(config.dpopNonceSecret, 'base64');
    if (dpopNonceSecret.length !== 32)
      throw new IamError('configuration', 'dpopNonceSecret must encode exactly 32 bytes.');
  }
  const clientLifetime = (client: unknown, key: 'access_token_ttl' | 'refresh_token_ttl') => {
    const value = (client as Record<string, unknown> | undefined)?.[key];
    return typeof value === 'number' && value > 0 ? value : undefined;
  };
  /** Per-request token exchange state: the actor claim and the subject token's remaining lifetime. */
  const exchanges = new WeakMap<object, { act: Record<string, unknown>; remaining: number }>();
  const accessTokenTtl = (
    token: { resourceServer?: { accessTokenTTL?: number } },
    client: unknown,
    ctx?: object,
  ): number =>
    Math.min(
      token.resourceServer?.accessTokenTTL ?? 900,
      clientLifetime(client, 'access_token_ttl') ?? Infinity,
      (ctx && exchanges.get(ctx)?.remaining) || Infinity,
    );
  const adapter = createProviderAdapter(
    config.store,
    config.encryptionKey,
    config.validateSession,
    config.registration
      ? (clientId, payload) => storeRegisteredClient(clientId, payload)
      : undefined,
  );
  const grants = new adapter('Grant');
  const secure = issuer.protocol === 'https:';
  const configuration: Configuration = {
    adapter,
    clients: [],
    jwks: config.jwks,
    cookies: {
      keys: config.cookieKeys,
      long: { httpOnly: true, secure, sameSite: 'lax' },
      short: { httpOnly: true, secure, sameSite: 'lax' },
    },
    // Outbound requests (JWKS URIs, back-channel logout) keep oidc-provider's special-use IP protection, except
    // for loopback targets during local development.
    ...(config.allowInsecureLocalhost
      ? {
          fetch: (url: string | URL | Request, options?: RequestInit) => {
            const target = new URL(url instanceof Request ? url.url : url);
            if (!loopback.includes(target.hostname)) return fetch(url, options);
            const { dispatcher: _dispatcher, ...direct } = (options ?? {}) as RequestInit & {
              dispatcher?: unknown;
            };
            return fetch(url, direct);
          },
        }
      : {}),
    responseTypes: ['code'],
    scopes: supportedScopes,
    pkce: { required: () => true },
    // OpenID requests follow OIDC: a refresh token needs `offline_access` (granted with prompt=consent). Plain OAuth 2.1
    // authorization codes (no `openid`, as MCP hosts send) get one whenever the client is registered for the refresh
    // grant; it still rotates and dies with the IAM session that consented.
    issueRefreshToken: async (_ctx, client, code) =>
      client.grantTypeAllowed('refresh_token') &&
      (code.scopes.has('offline_access') ||
        (code.kind === 'AuthorizationCode' && !code.scopes.has('openid'))),
    rotateRefreshToken: true,
    clientBasedCORS: (_ctx, origin, client) =>
      client.redirectUris?.some((uri) => new URL(uri).origin === origin) ?? false,
    features: {
      devInteractions: { enabled: false },
      // Open at the protocol level: the registration gate below admits only token holders and the anonymous hook.
      registration: config.registration
        ? { enabled: true, initialAccessToken: false, issueRegistrationAccessToken: false }
        : { enabled: false },
      registrationManagement: { enabled: false },
      clientCredentials: { enabled: true },
      pushedAuthorizationRequests: {
        enabled: true,
        requirePushedAuthorizationRequests: config.requirePushedAuthorizationRequests ?? false,
        allowUnregisteredRedirectUris: false,
      },
      dPoP: dpopNonceSecret
        ? { enabled: true, nonceSecret: dpopNonceSecret, allowReplay: false }
        : { enabled: true, allowReplay: false },
      resourceIndicators: {
        enabled: true,
        // Without an explicit `resource`, OpenID requests keep receiving UserInfo access tokens.
        useGrantedResource: () => false,
        getResourceServerInfo: async (_ctx, indicator, client) => {
          const server = resourceServers.get(indicator);
          const row = await config.store.get<ClientRow>('oauthClients', hash(client.clientId));
          if (!server || !row?.resources?.includes(indicator))
            throw new errors.InvalidTarget('The client may not request this resource.');
          return {
            scope: server.scopes.join(' '),
            audience: server.audience ?? indicator,
            accessTokenTTL: server.accessTokenTtl ?? 900,
            accessTokenFormat: server.accessTokenFormat ?? 'jwt',
          };
        },
      },
      introspection: {
        enabled: true,
        allowedPolicy: (_ctx, client, token) => client.clientId === token.clientId,
      },
      revocation: {
        enabled: true,
        allowedPolicy: (_ctx, client, token) => client.clientId === token.clientId,
      },
      deviceFlow: {
        enabled: true,
        userCodeInputSource: async (ctx, form) => {
          ctx.body = await config.renderDevicePage({ kind: 'input', form });
        },
        userCodeConfirmSource: async (ctx, form, client, _info, userCode) => {
          ctx.body = await config.renderDevicePage({
            kind: 'confirm',
            form,
            userCode,
            clientName: client.clientName,
          });
        },
        successSource: async (ctx) => {
          ctx.body = await config.renderDevicePage({ kind: 'success', form: '' });
        },
      },
      backchannelLogout: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, form) => {
          ctx.body = await config.renderLogoutPage({ form });
        },
      },
    },
    interactions: { url: (_ctx, interaction) => config.interactionUrl(interaction.uid) },
    claims: {
      openid: ['sub', 'tenant_id'],
      email: ['email', 'email_verified'],
      profile: ['name'],
      // The `iam` scope exposes the account's current role and group IDs and declared attributes.
      iam: ['roles', 'groups', 'attributes'],
    },
    extraClientMetadata: {
      properties: ['tenant_id', 'access_token_ttl', 'refresh_token_ttl'],
      validator: (_ctx, key, value, client) => {
        // Dynamic registrations get their tenant (and limits) from the registration gate, never from the request.
        const registering = key === 'tenant_id' ? registrationContext.getStore() : undefined;
        if (registering) {
          applyRegistrationPolicy(client as unknown as Record<string, unknown>, registering);
          return;
        }
        if (key === 'tenant_id' && (typeof value !== 'string' || !value))
          throw new errors.InvalidClientMetadata('tenant_id is required.');
        if (key !== 'tenant_id' && value !== undefined && !Number.isSafeInteger(value))
          throw new errors.InvalidClientMetadata(`${key} must be an integer.`);
      },
    },
    ttl: {
      // The shortest applicable lifetime wins: provider default, the resource server's, and the client's.
      AccessToken: (ctx, token, client) => accessTokenTtl(token, client, ctx),
      AuthorizationCode: 60,
      ClientCredentials: (_ctx, token, client) => accessTokenTtl(token, client),
      DeviceCode: 600,
      Grant: 30 * 86400,
      IdToken: 900,
      Interaction: 600,
      PushedAuthorizationRequest: 60,
      RefreshToken: (_ctx, _token, client) =>
        clientLifetime(client, 'refresh_token_ttl') ?? 30 * 86400,
      Session: 86400,
    },
    findAccount: async (ctx, accountId) => {
      const account = await config.store.get<Identity>('identities', accountId);
      if (
        !account ||
        account.status !== 'active' ||
        !(await tenantTreeActive(config.store, account.tenantId))
      )
        return undefined;
      if (ctx.oidc.client) {
        const row = await config.store.get<ClientRow>(
          'oauthClients',
          hash(ctx.oidc.client.clientId),
        );
        if (!row || row.revoked || row.tenantId !== account.tenantId) return undefined;
      }
      return {
        accountId,
        claims: async (_use, scope) => {
          const base = {
            sub: accountId,
            tenant_id: account.tenantId,
            email: account.email,
            email_verified: account.emailVerified,
            name: account.name,
          };
          if (!scope?.split(' ').includes('iam')) return base;
          // Live role and group membership at token time; expired bindings are excluded.
          const now = Date.now();
          const groups = (
            await config.store.find('groupMembers', {
              tenantId: account.tenantId,
              identityId: account.id,
            })
          ).map((membership) => String(membership.groupId));
          const roles = (await config.store.find('bindings', { tenantId: account.tenantId }))
            .filter(
              (binding) =>
                (typeof binding.expiresAt !== 'number' || binding.expiresAt > now) &&
                ((binding.subjectType === 'identity' && binding.subjectId === account.id) ||
                  (binding.subjectType === 'group' && groups.includes(String(binding.subjectId)))),
            )
            .map((binding) => String(binding.roleId));
          return {
            ...base,
            roles: [...new Set(roles)].sort(),
            groups: [...groups].sort(),
            attributes: account.attributes ?? {},
          };
        },
      };
    },
    extraTokenClaims: async (ctx, token) => {
      const exchange = ctx ? exchanges.get(ctx) : undefined;
      const row = token.clientId
        ? await config.store.get<ClientRow>('oauthClients', hash(token.clientId))
        : undefined;
      return row
        ? {
            tenant_id: row.tenantId,
            ...(row.serviceAccountId && !exchange ? { identity_id: row.serviceAccountId } : {}),
            ...(exchange ? { act: exchange.act } : {}),
          }
        : {};
    },
    renderError: async (ctx, out) => {
      ctx.type = 'application/json';
      ctx.body = {
        error: out.error,
        error_description: 'The identity request could not be completed.',
      };
    },
  };
  const provider = new Provider(config.issuer, configuration);
  provider.proxy = config.trustProxy ?? false;
  registerTokenExchange();
  installRegistrationGate();
  const callback = provider.callback();
  const basePath = issuer.pathname.replace(/\/$/, '');

  /**
   * Dynamic registration gate: `POST /reg` proceeds only with a live tenant registration token or a request the
   * `anonymous` hook maps to a tenant. The decision travels with the request so the client metadata validator and
   * the adapter can bind the new client to that tenant and its limits.
   */
  function installRegistrationGate(): void {
    const registration = config.registration;
    if (!registration) return;
    provider.use(async (ctx, next) => {
      if (ctx.method !== 'POST' || ctx.path !== '/reg') return next();
      const refuse = (description: string) => {
        ctx.status = 401;
        ctx.set('www-authenticate', 'Bearer error="invalid_token"');
        ctx.set('cache-control', 'no-store');
        ctx.body = { error: 'invalid_token', error_description: description };
      };
      const header = ctx.get('authorization');
      let context: RegistrationContext;
      if (header) {
        const match = /^Bearer ([A-Za-z0-9_-]{20,200})$/.exec(header);
        const record = match
          ? await config.store.get<RegistrationTokenRecord>(
              'oauthRegistrationTokens',
              hash(match[1]!),
            )
          : undefined;
        if (!record || !usableRegistrationToken(record))
          return refuse('The registration token is invalid, expired, or used up.');
        context = {
          tenantId: record.tenantId,
          scopes: record.scopes,
          resources: record.resources,
          allowConfidential: record.allowConfidential,
          maxClients: record.maxClients,
          tokenId: record.id,
          actorId: record.createdBy,
        };
      } else {
        const policy = await registration.anonymous?.({
          headers: ctx.headers as Record<string, string | string[] | undefined>,
          ip: ctx.ip,
        });
        if (!policy) return refuse('Registration requires a registration token.');
        const normalized = registrationLimits(policy);
        context = { ...normalized, actorId: 'dynamic-registration' };
      }
      if (!(await tenantTreeActive(config.store, context.tenantId)))
        return refuse('The tenant is unavailable.');
      await registrationContext.run(context, next);
    });
  }
  /** Validates an anonymous-registration policy from the host. */
  function registrationLimits(policy: RegistrationPolicy) {
    const scopes = [...new Set(policy.scopes ?? defaultRegistrationScopes)];
    const resources = [...new Set(policy.resources ?? [])];
    const maxClients = policy.maxClients ?? 100;
    if (
      typeof policy.tenantId !== 'string' ||
      !policy.tenantId ||
      !scopes.length ||
      scopes.some((scope) => !supportedScopes.includes(scope)) ||
      resources.some((indicator) => !resourceServers.has(indicator)) ||
      !Number.isSafeInteger(maxClients) ||
      maxClients < 1 ||
      maxClients > 100_000
    )
      throw new IamError('configuration', 'Invalid dynamic registration policy.');
    return {
      tenantId: policy.tenantId,
      scopes,
      resources,
      allowConfidential: policy.allowConfidential === true,
      maxClients,
    };
  }
  function registrationTokenSummary(record: RegistrationTokenRecord): RegistrationTokenSummary {
    return {
      id: record.id,
      tenantId: record.tenantId,
      name: record.name,
      scopes: [...record.scopes],
      resources: [...record.resources],
      allowConfidential: record.allowConfidential,
      maxClients: record.maxClients,
      used: record.used,
      createdBy: record.createdBy,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      revoked: record.revoked,
    };
  }
  function usableRegistrationToken(record: RegistrationTokenRecord): boolean {
    return !record.revoked && record.expiresAt > Date.now() && record.used < record.maxClients;
  }
  /**
   * The limits of a dynamic registration, applied to the requested metadata before oidc-provider validates it:
   * tenant binding, authorization code (and refresh) only, public clients unless allowed, HTTPS or loopback redirect
   * URIs (and reverse-domain custom schemes for native apps), no metadata that makes the provider fetch URLs, and
   * scopes within the allowance (the allowance itself when the client asks for none).
   */
  function applyRegistrationPolicy(
    client: Record<string, unknown>,
    registering: RegistrationContext,
  ): void {
    const refuse = (message: string) => {
      throw new errors.InvalidClientMetadata(message);
    };
    client.tenant_id = registering.tenantId;
    const grantTypes = Array.isArray(client.grant_types)
      ? (client.grant_types as unknown[])
      : ['authorization_code'];
    if (grantTypes.some((type) => type !== 'authorization_code' && type !== 'refresh_token'))
      refuse('Registered clients may use only the authorization_code and refresh_token grants.');
    const method = String(client.token_endpoint_auth_method ?? 'client_secret_basic');
    if (method !== 'none' && !registering.allowConfidential)
      refuse('Only public clients (token_endpoint_auth_method "none") may register here.');
    if (!['none', 'client_secret_basic', 'client_secret_post'].includes(method))
      refuse('Unsupported token_endpoint_auth_method for dynamic registration.');
    for (const key of [
      'jwks',
      'jwks_uri',
      'sector_identifier_uri',
      'backchannel_logout_uri',
      'request_uris',
      'initiate_login_uri',
      'access_token_ttl',
      'refresh_token_ttl',
    ])
      if (client[key] !== undefined) refuse(`${key} cannot be registered dynamically.`);
    const uris = [
      ...(Array.isArray(client.redirect_uris) ? client.redirect_uris : []),
      ...(Array.isArray(client.post_logout_redirect_uris) ? client.post_logout_redirect_uris : []),
    ];
    for (const uri of uris) {
      let parsed: URL;
      try {
        parsed = new URL(String(uri));
      } catch {
        return refuse('Redirect URIs must be absolute.');
      }
      const acceptable =
        !parsed.hash &&
        !parsed.username &&
        !parsed.password &&
        (parsed.protocol === 'https:' ||
          (parsed.protocol === 'http:' && loopback.includes(parsed.hostname)) ||
          /^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$/.test(parsed.protocol));
      if (!acceptable)
        refuse('Redirect URIs must use HTTPS, loopback HTTP, or a reverse-domain custom scheme.');
    }
    const requested =
      typeof client.scope === 'string' ? client.scope.split(' ').filter(Boolean) : [];
    if (!requested.length) client.scope = registering.scopes.join(' ');
    else if (requested.some((scope) => !registering.scopes.includes(scope)))
      refuse('The requested scope is not allowed for this registration.');
  }
  /** Persists a dynamically registered client inside the registration gate's tenant and limits. */
  async function storeRegisteredClient(clientId: string, payload: Record<string, unknown>) {
    const registering = registrationContext.getStore();
    if (!registering || payload.tenant_id !== registering.tenantId)
      throw new IamError('PROTECTED_OPERATION', 'Use authenticated registerClient().', 403);
    await config.store.transaction(async (tx) => {
      if (!(await tenantTreeActive(tx, registering.tenantId)))
        throw new errors.AccessDenied('The tenant is unavailable.');
      if (registering.tokenId) {
        const token = await tx.get<RegistrationTokenRecord>(
          'oauthRegistrationTokens',
          registering.tokenId,
        );
        if (!token || !usableRegistrationToken(token))
          throw new errors.InvalidToken('The registration token is no longer usable.');
        await tx.put<RegistrationTokenRecord>('oauthRegistrationTokens', {
          ...token,
          used: token.used + 1,
        });
      } else {
        const registered = await tx.find<ClientRow>('oauthClients', {
          tenantId: registering.tenantId,
          registeredVia: 'anonymous',
        });
        if (registered.length >= registering.maxClients)
          throw new errors.AccessDenied('The tenant has reached its registration limit.');
      }
      if (await tx.get('oauthClients', hash(clientId)))
        throw new errors.InvalidClientMetadata('The client ID is taken.');
      const now = Date.now();
      await tx.insert<ClientRow>('oauthClients', {
        id: hash(clientId),
        tenantId: registering.tenantId,
        clientId,
        encrypted: crypt.seal(payload),
        revoked: false,
        resources: registering.resources,
        registeredVia: registering.tokenId ?? 'anonymous',
        createdAt: now,
        updatedAt: now,
      });
      await audit(
        tx,
        registering.tenantId,
        registering.actorId,
        'iam:oauth:RegisterClient',
        clientId,
      );
    });
  }

  /**
   * RFC 8693 token exchange for delegation: a confidential client presents an access token it received and gets a
   * token for one of its own resources, carrying only scopes it is registered for, on behalf of the same account.
   * The issued token names the client in `act` and never outlives the subject token.
   */
  function registerTokenExchange(): void {
    const verificationKeys = createLocalJWKSet({
      keys: config.jwks.keys.map((key) => {
        const {
          d: _d,
          p: _p,
          q: _q,
          dp: _dp,
          dq: _dq,
          qi: _qi,
          k: _k,
          ...publicKey
        } = key as Record<string, unknown>;
        return publicKey;
      }),
    });
    provider.registerGrantType(
      TOKEN_EXCHANGE,
      async (ctx) => {
        const { params, client } = ctx.oidc;
        const value = (name: string) => {
          const raw = (params as Record<string, unknown>)[name];
          if (Array.isArray(raw))
            throw new errors.InvalidRequest(`${name} must be given at most once.`);
          return typeof raw === 'string' && raw ? raw : undefined;
        };
        const subjectToken = value('subject_token');
        if (!subjectToken || value('subject_token_type') !== ACCESS_TOKEN_TYPE)
          throw new errors.InvalidRequest(
            'subject_token must be an access token from this issuer.',
          );
        const requested = value('requested_token_type');
        if (requested && requested !== ACCESS_TOKEN_TYPE)
          throw new errors.InvalidRequest('Only access tokens can be requested.');
        if (value('actor_token'))
          throw new errors.InvalidRequest('actor_token is not supported; the client is the actor.');
        const row = await config.store.get<ClientRow>('oauthClients', hash(client.clientId));
        if (!row || row.revoked) throw new errors.InvalidClient('Client is unavailable.');
        const subject = await exchangedSubject(subjectToken, verificationKeys);
        const identity = await config.store.get<Identity>('identities', subject.identityId);
        if (
          !identity ||
          identity.status !== 'active' ||
          identity.tenantId !== row.tenantId ||
          !(await tenantTreeActive(config.store, row.tenantId))
        )
          throw new errors.InvalidGrant('The subject token is not usable by this client.');
        const indicator = value('resource') ?? value('audience');
        const server = indicator ? resourceServers.get(indicator) : undefined;
        if (!indicator || !server || !row.resources?.includes(indicator))
          throw new errors.InvalidTarget('Name one resource this client may call.');
        const clientScopes = String(client.scope ?? '').split(' ');
        const allowed = server.scopes.filter((scope) => clientScopes.includes(scope));
        const scopes = value('scope')?.split(' ').filter(Boolean) ?? allowed;
        const refused = scopes.filter((scope) => !allowed.includes(scope));
        if (refused.length || !scopes.length)
          throw new errors.InvalidScope('The requested scope is not allowed.', refused.join(' '));
        const remaining = subject.expiresAt - Math.floor(Date.now() / 1000);
        if (remaining <= 0) throw new errors.InvalidGrant('The subject token has expired.');
        const request: TokenExchangeRequest = {
          tenantId: row.tenantId,
          clientId: client.clientId,
          identityId: subject.identityId,
          subjectClientId: subject.clientId,
          subjectScopes: subject.scopes,
          resource: indicator,
          scopes,
        };
        if (config.authorizeTokenExchange && !(await config.authorizeTokenExchange(request)))
          throw new errors.AccessDenied('The token exchange is not permitted.');
        exchanges.set(ctx, {
          act: { sub: client.clientId, ...(subject.act ? { act: subject.act } : {}) },
          remaining,
        });
        const resourceServer = new provider.ResourceServer(indicator, {
          scope: server.scopes.join(' '),
          audience: server.audience ?? indicator,
          accessTokenTTL: server.accessTokenTtl ?? 900,
          accessTokenFormat: server.accessTokenFormat ?? 'jwt',
        });
        const token = new provider.AccessToken({
          client,
          accountId: subject.identityId,
          grantId: subject.grantId ?? '',
          gty: 'token_exchange',
          scope: scopes.join(' '),
          resourceServer,
        });
        const issued = await token.save();
        await config.store.transaction((tx) =>
          audit(tx, row.tenantId, subject.identityId, 'iam:oauth:TokenExchange', client.clientId),
        );
        ctx.body = {
          access_token: issued,
          issued_token_type: ACCESS_TOKEN_TYPE,
          token_type: 'Bearer',
          expires_in: token.expiration,
          scope: scopes.join(' '),
        };
      },
      [
        'subject_token',
        'subject_token_type',
        'actor_token',
        'actor_token_type',
        'requested_token_type',
        'audience',
        'resource',
        'scope',
      ],
      ['audience', 'resource'],
    );
  }
  /**
   * The account behind a subject token: a JWT access token signed by this issuer, or an opaque access token it
   * stores. Sender-constrained tokens are refused because the exchanging client cannot prove their key.
   */
  async function exchangedSubject(
    value: string,
    keys: ReturnType<typeof createLocalJWKSet>,
  ): Promise<{
    identityId: string;
    clientId: string;
    scopes: string[];
    expiresAt: number;
    grantId?: string;
    act?: unknown;
  }> {
    if (value.split('.').length === 3) {
      let claims: Record<string, unknown>;
      try {
        ({ payload: claims } = await jwtVerify(value, keys, {
          issuer: config.issuer,
          typ: 'at+jwt',
          requiredClaims: ['exp', 'client_id', 'sub'],
        }));
      } catch {
        throw new errors.InvalidGrant('The subject token is invalid.');
      }
      if ((claims.cnf as { jkt?: unknown } | undefined)?.jkt)
        throw new errors.InvalidGrant('Sender-constrained tokens cannot be exchanged.');
      const identityId =
        typeof claims.identity_id === 'string' ? claims.identity_id : String(claims.sub);
      return {
        identityId,
        clientId: String(claims.client_id),
        scopes: typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [],
        expiresAt: Number(claims.exp),
        ...(claims.act ? { act: claims.act } : {}),
      };
    }
    const token = await provider.AccessToken.find(value);
    if (!token || token.isExpired || !token.accountId)
      throw new errors.InvalidGrant('The subject token is invalid.');
    if (token.isSenderConstrained())
      throw new errors.InvalidGrant('Sender-constrained tokens cannot be exchanged.');
    return {
      identityId: token.accountId,
      clientId: token.clientId!,
      scopes: String(token.scope ?? '')
        .split(' ')
        .filter(Boolean),
      expiresAt: token.exp!,
      ...(token.grantId ? { grantId: token.grantId } : {}),
      ...(token.extra?.act ? { act: token.extra.act } : {}),
    };
  }
  async function audit(
    tx: IamStore,
    tenantId: string,
    actorId: string,
    action: string,
    resourceId: string,
  ): Promise<void> {
    await appendAuditEvent(tx, {
      id: randomUUID(),
      tenantId,
      actorId,
      action,
      resourceId,
      timestamp: Date.now(),
      outcome: 'allow',
    });
  }
  async function clientRow(clientId: string): Promise<ClientRow> {
    const row = await config.store.get<ClientRow>('oauthClients', hash(clientId));
    if (!row || row.revoked || !(await tenantTreeActive(config.store, row.tenantId)))
      throw new IamError('OAUTH_CLIENT', 'Client is unavailable.', 404);
    return row;
  }
  /** A client of `tenantId`, including revoked ones; foreign clients are indistinguishable from missing ones. */
  async function tenantClient(tx: IamStore, tenantId: string, clientId: string) {
    const row =
      typeof clientId === 'string' && clientId
        ? await tx.get<ClientRow>('oauthClients', hash(clientId))
        : undefined;
    if (!row || row.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'Client not found.', 404);
    return row;
  }
  function summary(row: ClientRow): OAuthClientSummary {
    const metadata = crypt.open<ClientMetadata>(row.encrypted);
    return {
      clientId: row.clientId,
      tenantId: row.tenantId,
      name: String(metadata.client_name ?? row.clientId),
      public: metadata.token_endpoint_auth_method === 'none',
      redirectUris: [...(metadata.redirect_uris ?? [])],
      postLogoutRedirectUris: [...(metadata.post_logout_redirect_uris ?? [])],
      grantTypes: (metadata.grant_types ?? []) as OAuthGrantType[],
      scopes: String(metadata.scope ?? '')
        .split(' ')
        .filter(Boolean),
      resources: row.resources ?? [],
      requireDpop: metadata.dpop_bound_access_tokens === true,
      requirePushedAuthorization: metadata.require_pushed_authorization_requests === true,
      tokenEndpointAuthMethod: (metadata.token_endpoint_auth_method ??
        'client_secret_basic') as OAuthClientSummary['tokenEndpointAuthMethod'],
      ...(metadata.backchannel_logout_uri
        ? { backchannelLogoutUri: metadata.backchannel_logout_uri }
        : {}),
      ...(typeof metadata.access_token_ttl === 'number'
        ? { accessTokenTtl: metadata.access_token_ttl }
        : {}),
      ...(typeof metadata.refresh_token_ttl === 'number'
        ? { refreshTokenTtl: metadata.refresh_token_ttl }
        : {}),
      ...(metadata.jwks_uri ? { jwksUri: metadata.jwks_uri } : {}),
      ...(metadata.jwks
        ? { keyIds: metadata.jwks.keys.map((key) => String(key.kid ?? key.kty)) }
        : {}),
      ...(row.serviceAccountId ? { serviceAccountId: row.serviceAccountId } : {}),
      revoked: row.revoked,
      ...(metadata.logo_uri ? { logoUri: metadata.logo_uri } : {}),
      ...(metadata.client_uri ? { clientUri: metadata.client_uri } : {}),
      ...(metadata.policy_uri ? { policyUri: metadata.policy_uri } : {}),
      ...(metadata.tos_uri ? { tosUri: metadata.tos_uri } : {}),
      firstParty: row.firstParty === true,
      ...(row.registeredVia ? { registeredVia: row.registeredVia } : {}),
      ...(row.createdAt ? { createdAt: row.createdAt } : {}),
      ...(row.updatedAt ? { updatedAt: row.updatedAt } : {}),
      ...(row.secretRotatedAt ? { secretRotatedAt: row.secretRotatedAt } : {}),
    };
  }
  /** Validates client settings and returns the normalized protocol metadata (without identity or secret fields). */
  function settings(
    input: OAuthClientSettings,
    authMethod: OAuthClientAuthMethod | 'none',
    serviceAccountId?: string,
  ) {
    const isPublic = authMethod === 'none';
    if (
      typeof input.name !== 'string' ||
      !input.name ||
      input.name.length > 200 ||
      !Array.isArray(input.redirectUris) ||
      input.redirectUris.length > 20 ||
      (input.postLogoutRedirectUris !== undefined &&
        (!Array.isArray(input.postLogoutRedirectUris) || input.postLogoutRedirectUris.length > 20))
    )
      throw new IamError('INVALID_INPUT', 'Invalid client configuration.');
    for (const uri of [...input.redirectUris, ...(input.postLogoutRedirectUris ?? [])]) {
      let parsed: URL;
      try {
        parsed = new URL(uri);
      } catch {
        throw new IamError('INVALID_INPUT', 'Client redirect URIs must be absolute URLs.');
      }
      if (parsed.hash || parsed.username || parsed.password || !secureOrLocal(parsed))
        throw new IamError('INVALID_INPUT', 'Client redirect URIs require HTTPS.');
    }
    const grantTypes = input.grantTypes ?? ['authorization_code', 'refresh_token'];
    if (
      !Array.isArray(grantTypes) ||
      !grantTypes.length ||
      grantTypes.some((type) => !grantTypesSupported.includes(type)) ||
      (isPublic &&
        (grantTypes.includes('client_credentials') || grantTypes.includes(TOKEN_EXCHANGE)))
    )
      throw new IamError('INVALID_INPUT', 'Unsupported client grant types.');
    if (grantTypes.includes('authorization_code') && !input.redirectUris.length)
      throw new IamError('INVALID_INPUT', 'Authorization code clients need a redirect URI.');
    const scopes = input.scopes ?? ['openid', 'email', 'profile', 'offline_access'];
    if (!Array.isArray(scopes) || scopes.some((scope) => !supportedScopes.includes(scope)))
      throw new IamError('INVALID_INPUT', 'Unsupported OAuth scope.');
    const resources = [...new Set(input.resources ?? [])];
    if (resources.some((indicator) => !resourceServers.has(indicator)))
      throw new IamError('INVALID_INPUT', 'Unknown resource indicator.');
    if (grantTypes.includes('client_credentials') && !serviceAccountId)
      throw new IamError('INVALID_INPUT', 'Client credentials require a tenant service account.');
    if (
      (input.requireDpop !== undefined && typeof input.requireDpop !== 'boolean') ||
      (input.requirePushedAuthorization !== undefined &&
        typeof input.requirePushedAuthorization !== 'boolean')
    )
      throw new IamError('INVALID_INPUT', 'Invalid client configuration.');
    const secureUrl = (value: unknown, label: string) => {
      let parsed: URL;
      try {
        parsed = new URL(String(value));
      } catch {
        throw new IamError('INVALID_INPUT', `${label} must be an absolute URL.`);
      }
      if (
        typeof value !== 'string' ||
        parsed.hash ||
        parsed.username ||
        parsed.password ||
        !secureOrLocal(parsed)
      )
        throw new IamError('INVALID_INPUT', `${label} requires HTTPS.`);
      return value;
    };
    const lifetime = (value: unknown, min: number, max: number, label: string) => {
      if (
        value !== undefined &&
        (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max)
      )
        throw new IamError('INVALID_INPUT', ` must be an integer from ${min} to ${max} seconds.`);
    };
    lifetime(input.accessTokenTtl, 60, 86400, 'accessTokenTtl');
    lifetime(input.refreshTokenTtl, 300, 30 * 86400, 'refreshTokenTtl');
    if (input.backchannelLogoutUri !== undefined)
      secureUrl(input.backchannelLogoutUri, 'The back-channel logout URI');
    for (const [value, label] of [
      [input.logoUri, 'The logo URI'],
      [input.clientUri, 'The client URI'],
      [input.policyUri, 'The policy URI'],
      [input.tosUri, 'The terms of service URI'],
    ] as const)
      if (value !== undefined) secureUrl(value, label);
    if (input.firstParty !== undefined && typeof input.firstParty !== 'boolean')
      throw new IamError('INVALID_INPUT', 'firstParty must be a boolean.');
    if (authMethod === 'private_key_jwt') {
      if ((input.jwks === undefined) === (input.jwksUri === undefined))
        throw new IamError('INVALID_INPUT', 'private_key_jwt clients need either jwks or jwksUri.');
      if (input.jwksUri !== undefined) secureUrl(input.jwksUri, 'The JWKS URI');
      if (
        input.jwks !== undefined &&
        (!Array.isArray(input.jwks?.keys) ||
          !input.jwks.keys.length ||
          input.jwks.keys.length > 10 ||
          input.jwks.keys.some(
            (key) =>
              !key ||
              typeof key !== 'object' ||
              typeof key.kty !== 'string' ||
              ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].some((member) => member in key),
          ))
      )
        throw new IamError('INVALID_INPUT', 'jwks must hold one to ten public keys.');
    } else if (input.jwks !== undefined || input.jwksUri !== undefined)
      throw new IamError('INVALID_INPUT', 'Only private_key_jwt clients register keys.');
    const metadata: Omit<ClientMetadata, 'client_id'> = {
      client_name: input.name,
      redirect_uris: input.redirectUris,
      grant_types: grantTypes,
      response_types: grantTypes.includes('authorization_code') ? ['code'] : [],
      scope: [...new Set(scopes)].join(' '),
      post_logout_redirect_uris: input.postLogoutRedirectUris ?? [],
      ...(input.requireDpop ? { dpop_bound_access_tokens: true } : {}),
      ...(input.requirePushedAuthorization ? { require_pushed_authorization_requests: true } : {}),
      ...(input.backchannelLogoutUri
        ? {
            backchannel_logout_uri: input.backchannelLogoutUri,
            backchannel_logout_session_required: false,
          }
        : {}),
      ...(input.logoUri ? { logo_uri: input.logoUri } : {}),
      ...(input.clientUri ? { client_uri: input.clientUri } : {}),
      ...(input.policyUri ? { policy_uri: input.policyUri } : {}),
      ...(input.tosUri ? { tos_uri: input.tosUri } : {}),
      ...(input.accessTokenTtl !== undefined ? { access_token_ttl: input.accessTokenTtl } : {}),
      ...(input.refreshTokenTtl !== undefined ? { refresh_token_ttl: input.refreshTokenTtl } : {}),
      ...(authMethod === 'private_key_jwt' && input.jwks ? { jwks: input.jwks } : {}),
      ...(authMethod === 'private_key_jwt' && input.jwksUri ? { jwks_uri: input.jwksUri } : {}),
    };
    return { metadata, resources, firstParty: input.firstParty === true };
  }
  /** Deletes every artifact issued to a client (tokens, codes, grants). */
  async function purgeClientArtifacts(tx: IamStore, clientId: string): Promise<void> {
    for (const record of await tx.find<Artifact>('oauthArtifacts', { clientId }))
      await tx.delete('oauthArtifacts', record.id);
  }
  /**
   * The account whose connected apps are read or changed. Callers manage their own grants; anyone else needs
   * `iam:oauth:grants:{read,revoke}` on `iam/{identityId}` in the account's tenant.
   */
  async function grantOwner(
    credential: CredentialInput,
    tenantId: string,
    identityId: string | undefined,
    action: 'iam:oauth:grants:read' | 'iam:oauth:grants:revoke',
  ): Promise<{ principal: AuthenticatedPrincipal; identityId: string }> {
    const principal = await config.authenticate(credential);
    const target = identityId ?? principal.identity.id;
    if (target !== principal.identity.id || tenantId !== principal.identity.tenantId) {
      await config.authorize(credential, action, { tenantId, type: 'iam', id: target });
      const identity = await config.store.get<Identity>('identities', target);
      if (!identity || identity.tenantId !== tenantId)
        throw new IamError('NOT_FOUND', 'Identity not found.', 404);
    }
    return { principal, identityId: target };
  }
  /** Live grants of an account: expired, revoked, and session-orphaned grants are omitted. */
  async function accountGrants(tenantId: string, identityId: string) {
    const live: { row: Artifact; grantId: string; summary: OAuthGrantSummary }[] = [];
    const names = new Map<string, string>();
    for (const row of await config.store.find<Artifact>('oauthArtifacts', {
      model: 'Grant',
      accountId: identityId,
    })) {
      if (row.boundTenantId !== tenantId || row.expiresAt <= Date.now() || !row.clientId) continue;
      const sealed = crypt.open<{ jti?: string }>(row.encrypted);
      const payload = sealed.jti ? await grants.find(sealed.jti) : undefined;
      if (!payload || !sealed.jti) continue;
      if (!names.has(row.clientId)) {
        const client = await config.store.get<ClientRow>('oauthClients', hash(row.clientId));
        if (!client || client.revoked) continue;
        names.set(row.clientId, summary(client).name);
      }
      const openid = (payload.openid ?? {}) as { scope?: string; claims?: string[] };
      const resources = (payload.resources ?? {}) as Record<string, string>;
      live.push({
        row,
        grantId: sealed.jti,
        summary: {
          id: row.id,
          tenantId,
          identityId,
          clientId: row.clientId,
          clientName: names.get(row.clientId)!,
          scopes: String(openid.scope ?? '')
            .split(' ')
            .filter(Boolean),
          claims: openid.claims ?? [],
          resources: Object.fromEntries(
            Object.entries(resources).map(([indicator, scope]) => [
              indicator,
              String(scope).split(' ').filter(Boolean),
            ]),
          ),
          createdAt: typeof payload.iat === 'number' ? payload.iat * 1000 : 0,
          expiresAt: row.expiresAt,
        },
      });
    }
    return live.sort(
      (a, b) => b.summary.createdAt - a.summary.createdAt || (a.summary.id < b.summary.id ? -1 : 1),
    );
  }
  async function revokeGrantIds(
    principal: AuthenticatedPrincipal,
    tenantId: string,
    revoked: { grantId: string; summary: OAuthGrantSummary }[],
  ): Promise<void> {
    for (const grant of revoked) await grants.revokeByGrantId(grant.grantId);
    if (!revoked.length) return;
    await config.store.transaction(async (tx) => {
      for (const grant of revoked)
        await audit(
          tx,
          tenantId,
          principal.identity.id,
          'iam:oauth:RevokeGrant',
          grant.summary.clientId,
        );
    });
  }

  return {
    basePath,
    /** Complete provider mount. Atomic artifact operations do not hold database locks while reading network bodies. */
    async nodeHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
      const original = req.url;
      const mounted = req as IncomingMessage & { originalUrl?: string };
      const previousOriginalUrl = mounted.originalUrl;
      mounted.originalUrl ??= req.url;
      const path = new URL(req.url ?? '/', issuer).pathname;
      const oauthDiscovery = `/.well-known/oauth-authorization-server${basePath}`;
      if (path === oauthDiscovery) req.url = '/.well-known/oauth-authorization-server';
      else if (basePath && path.startsWith(`${basePath}/`))
        req.url = req.url!.slice(basePath.length);
      try {
        await callback(req, res);
      } finally {
        req.url = original;
        if (previousOriginalUrl === undefined) delete mounted.originalUrl;
        else mounted.originalUrl = previousOriginalUrl;
      }
    },
    /** Registers a tenant-bound client; a confidential client receives its secret once. */
    async registerClient(credential: CredentialInput, input: RegisterOAuthClient) {
      if (
        typeof input.clientId !== 'string' ||
        !input.clientId ||
        input.clientId.length > 128 ||
        !input.name
      )
        throw new IamError('INVALID_INPUT', 'Invalid client configuration.');
      const authMethod = input.public
        ? 'none'
        : (input.tokenEndpointAuthMethod ?? 'client_secret_basic');
      if (
        (input.public && input.tokenEndpointAuthMethod !== undefined) ||
        !['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'].includes(
          authMethod,
        )
      )
        throw new IamError('INVALID_INPUT', 'Unsupported client authentication method.');
      const {
        metadata: base,
        resources,
        firstParty,
      } = settings(input, authMethod, input.serviceAccountId);
      const secret = authMethod.startsWith('client_secret_')
        ? randomBytes(32).toString('base64url')
        : undefined;
      const metadata: ClientMetadata = {
        client_id: input.clientId,
        tenant_id: input.tenantId,
        client_secret: secret,
        token_endpoint_auth_method: authMethod,
        ...base,
      };
      await config.store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:oauth:clients:create', {
          tenantId: input.tenantId,
          type: 'oauth-client',
          id: input.clientId,
        });
        const principal = await config.authenticate(credential);
        if (!(await tenantTreeActive(tx, input.tenantId)))
          throw new IamError('TENANT_INACTIVE', 'Tenant is unavailable.', 403);
        if (input.serviceAccountId) {
          const service = await tx.get<Identity>('identities', input.serviceAccountId);
          if (
            !service ||
            service.kind !== 'service' ||
            service.status !== 'active' ||
            service.tenantId !== input.tenantId
          )
            throw new IamError(
              'INVALID_INPUT',
              'An active service account in the client tenant is required.',
            );
        }
        if (await tx.get('oauthClients', hash(input.clientId)))
          throw new IamError(
            'CONFLICT',
            'Client ID already exists; tenant binding is immutable.',
            409,
          );
        const now = Date.now();
        await tx.insert<ClientRow>('oauthClients', {
          id: hash(input.clientId),
          tenantId: input.tenantId,
          clientId: input.clientId,
          encrypted: crypt.seal(metadata),
          revoked: false,
          serviceAccountId: input.serviceAccountId,
          resources,
          firstParty,
          createdAt: now,
          updatedAt: now,
        });
        await provider.Client.find(input.clientId);
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:RegisterClient',
          input.clientId,
        );
      });
      return { clientId: input.clientId, clientSecret: secret, tenantId: input.tenantId };
    },
    /**
     * Issues a tenant-scoped initial access token for dynamic client registration (`iam:oauth:clients:create`).
     * Each registration consumes one use; clients inherit the token's scope, resource, and confidentiality limits.
     */
    async createRegistrationToken(
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        /** Seconds until the token stops working (default 7 days, at most 1 year). */
        expiresIn?: number;
        maxClients?: number;
        scopes?: string[];
        resources?: string[];
        allowConfidential?: boolean;
      },
    ): Promise<RegistrationTokenSummary & { token: string }> {
      if (!config.registration)
        throw new IamError('configuration', 'Dynamic registration is not enabled.');
      const expiresIn = input.expiresIn ?? 7 * 86400;
      if (
        typeof input.name !== 'string' ||
        !input.name.trim() ||
        input.name.length > 200 ||
        !Number.isSafeInteger(expiresIn) ||
        expiresIn < 60 ||
        expiresIn > 365 * 86400
      )
        throw new IamError(
          'INVALID_INPUT',
          'A name and a lifetime between one minute and one year are required.',
        );
      let limits: ReturnType<typeof registrationLimits>;
      try {
        limits = registrationLimits({ ...input, maxClients: input.maxClients ?? 1 });
      } catch {
        throw new IamError('INVALID_INPUT', 'Unsupported scopes, resources, or client limit.');
      }
      await config.authorize(credential, 'iam:oauth:clients:create', {
        tenantId: input.tenantId,
        type: 'oauth-client',
        id: '*',
      });
      const principal = await config.authenticate(credential);
      const token = randomBytes(32).toString('base64url');
      const now = Date.now();
      const record: RegistrationTokenRecord = {
        id: hash(token),
        tenantId: input.tenantId,
        name: input.name.trim(),
        scopes: limits.scopes,
        resources: limits.resources,
        allowConfidential: limits.allowConfidential,
        maxClients: limits.maxClients,
        used: 0,
        createdBy: principal.identity.id,
        createdAt: now,
        expiresAt: now + expiresIn * 1000,
        revoked: false,
      };
      await config.store.transaction(async (tx) => {
        if (!(await tenantTreeActive(tx, input.tenantId)))
          throw new IamError('TENANT_INACTIVE', 'Tenant is unavailable.', 403);
        await tx.insert('oauthRegistrationTokens', record);
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:CreateRegistrationToken',
          record.id,
        );
      });
      return { ...registrationTokenSummary(record), token };
    },
    /** A tenant's registration tokens without their values (`iam:oauth:clients:read`). */
    async listRegistrationTokens(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<RegistrationTokenSummary[]> {
      await config.authorize(credential, 'iam:oauth:clients:read', {
        tenantId: input.tenantId,
        type: 'oauth-client',
        id: '*',
      });
      return (
        await config.store.find<RegistrationTokenRecord>('oauthRegistrationTokens', {
          tenantId: input.tenantId,
        })
      )
        .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1))
        .map(registrationTokenSummary);
    },
    /** Stops a registration token; clients it already registered stay (`iam:oauth:clients:delete`). */
    async revokeRegistrationToken(
      credential: CredentialInput,
      input: { tenantId: string; tokenId: string },
    ): Promise<void> {
      await config.authorize(credential, 'iam:oauth:clients:delete', {
        tenantId: input.tenantId,
        type: 'oauth-client',
        id: '*',
      });
      const principal = await config.authenticate(credential);
      await config.store.transaction(async (tx) => {
        const record =
          typeof input.tokenId === 'string' && /^[0-9a-f]{64}$/.test(input.tokenId)
            ? await tx.get<RegistrationTokenRecord>('oauthRegistrationTokens', input.tokenId)
            : undefined;
        if (!record || record.tenantId !== input.tenantId)
          throw new IamError('NOT_FOUND', 'Registration token not found.', 404);
        await tx.put('oauthRegistrationTokens', { ...record, revoked: true });
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:RevokeRegistrationToken',
          record.id,
        );
      });
    },
    /** Clients of a tenant the caller may read (`iam:oauth:clients:read` on each `oauth-client`). */
    async listClients(
      credential: CredentialInput,
      input: { tenantId: string; includeRevoked?: boolean },
    ): Promise<OAuthClientSummary[]> {
      await config.authenticate(credential);
      const visible: OAuthClientSummary[] = [];
      for (const row of await config.store.find<ClientRow>('oauthClients', {
        tenantId: input.tenantId,
      })) {
        if (row.revoked && !input.includeRevoked) continue;
        try {
          await config.authorize(credential, 'iam:oauth:clients:read', {
            tenantId: input.tenantId,
            type: 'oauth-client',
            id: row.clientId,
          });
        } catch (error) {
          if (error instanceof IamError && (error.status === 403 || error.status === 404)) continue;
          throw error;
        }
        visible.push(summary(row));
      }
      return visible.sort((a, b) => (a.clientId < b.clientId ? -1 : 1));
    },
    async getClient(
      credential: CredentialInput,
      input: { tenantId: string; clientId: string },
    ): Promise<OAuthClientSummary> {
      await config.authorize(credential, 'iam:oauth:clients:read', {
        tenantId: input.tenantId,
        type: 'oauth-client',
        id: input.clientId,
      });
      return summary(await tenantClient(config.store, input.tenantId, input.clientId));
    },
    /**
     * Changes client settings. Removing a grant type, scope, or resource revokes every outstanding token, code,
     * and consent of the client so no credential keeps authority the client no longer has.
     */
    async updateClient(
      credential: CredentialInput,
      input: UpdateOAuthClient,
    ): Promise<OAuthClientSummary & { tokensRevoked: boolean }> {
      return config.store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:oauth:clients:update', {
          tenantId: input.tenantId,
          type: 'oauth-client',
          id: input.clientId,
        });
        const principal = await config.authenticate(credential);
        const row = await tenantClient(tx, input.tenantId, input.clientId);
        if (row.revoked) throw new IamError('OAUTH_CLIENT', 'Client is unavailable.', 404);
        const current = summary(row);
        const next: OAuthClientSettings = {
          name: input.name ?? current.name,
          redirectUris: input.redirectUris ?? current.redirectUris,
          postLogoutRedirectUris: input.postLogoutRedirectUris ?? current.postLogoutRedirectUris,
          grantTypes: input.grantTypes ?? current.grantTypes,
          scopes: input.scopes ?? current.scopes,
          resources: input.resources ?? current.resources,
          requireDpop: input.requireDpop ?? current.requireDpop,
          requirePushedAuthorization:
            input.requirePushedAuthorization ?? current.requirePushedAuthorization,
          backchannelLogoutUri:
            input.backchannelLogoutUri === null
              ? undefined
              : (input.backchannelLogoutUri ?? current.backchannelLogoutUri),
          accessTokenTtl:
            input.accessTokenTtl === null
              ? undefined
              : (input.accessTokenTtl ?? current.accessTokenTtl),
          refreshTokenTtl:
            input.refreshTokenTtl === null
              ? undefined
              : (input.refreshTokenTtl ?? current.refreshTokenTtl),
          logoUri: input.logoUri === null ? undefined : (input.logoUri ?? current.logoUri),
          clientUri: input.clientUri === null ? undefined : (input.clientUri ?? current.clientUri),
          policyUri: input.policyUri === null ? undefined : (input.policyUri ?? current.policyUri),
          tosUri: input.tosUri === null ? undefined : (input.tosUri ?? current.tosUri),
          firstParty: input.firstParty ?? current.firstParty,
        };
        const previous = crypt.open<ClientMetadata>(row.encrypted);
        // Signing keys: new inline keys or a new URL replace whichever the client had.
        if (input.jwks !== undefined) next.jwks = input.jwks;
        else if (input.jwksUri !== undefined) next.jwksUri = input.jwksUri;
        else if (previous.jwks) next.jwks = previous.jwks as JWKS;
        else if (previous.jwks_uri) next.jwksUri = previous.jwks_uri;
        const {
          metadata: base,
          resources,
          firstParty,
        } = settings(next, current.tokenEndpointAuthMethod, row.serviceAccountId);
        const metadata: ClientMetadata = {
          client_id: previous.client_id,
          tenant_id: previous.tenant_id,
          client_secret: previous.client_secret,
          token_endpoint_auth_method: previous.token_endpoint_auth_method,
          ...base,
        };
        const narrowed = (before: string[], after: string[]) =>
          before.some((value) => !after.includes(value));
        const tokensRevoked =
          narrowed(current.grantTypes, next.grantTypes!) ||
          narrowed(current.scopes, next.scopes!) ||
          narrowed(current.resources, resources) ||
          (!current.requireDpop && next.requireDpop === true);
        await tx.put<ClientRow>('oauthClients', {
          ...row,
          encrypted: crypt.seal(metadata),
          resources,
          firstParty,
          updatedAt: Date.now(),
        });
        if (tokensRevoked) await purgeClientArtifacts(tx, row.clientId);
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:UpdateClient',
          input.clientId,
        );
        return { ...summary((await tx.get<ClientRow>('oauthClients', row.id))!), tokensRevoked };
      });
    },
    /**
     * Replaces a confidential client's secret; the previous secret stops working immediately. `revokeTokens`
     * also invalidates everything issued to the client (use it when the old secret leaked).
     */
    async rotateClientSecret(
      credential: CredentialInput,
      input: { tenantId: string; clientId: string; revokeTokens?: boolean },
    ): Promise<{ clientId: string; clientSecret: string; tenantId: string }> {
      const secret = randomBytes(32).toString('base64url');
      await config.store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:oauth:clients:update', {
          tenantId: input.tenantId,
          type: 'oauth-client',
          id: input.clientId,
        });
        const principal = await config.authenticate(credential);
        const row = await tenantClient(tx, input.tenantId, input.clientId);
        if (row.revoked) throw new IamError('OAUTH_CLIENT', 'Client is unavailable.', 404);
        const metadata = crypt.open<ClientMetadata>(row.encrypted);
        if (!String(metadata.token_endpoint_auth_method).startsWith('client_secret_'))
          throw new IamError('INVALID_INPUT', 'Only secret-authenticated clients have a secret.');
        const now = Date.now();
        await tx.put<ClientRow>('oauthClients', {
          ...row,
          encrypted: crypt.seal({ ...metadata, client_secret: secret }),
          updatedAt: now,
          secretRotatedAt: now,
        });
        if (input.revokeTokens) await purgeClientArtifacts(tx, row.clientId);
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:RotateClientSecret',
          input.clientId,
        );
      });
      return { clientId: input.clientId, clientSecret: secret, tenantId: input.tenantId };
    },
    async revokeClient(credential: CredentialInput, input: { tenantId: string; clientId: string }) {
      await config.store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:oauth:clients:delete', {
          tenantId: input.tenantId,
          type: 'oauth-client',
          id: input.clientId,
        });
        const principal = await config.authenticate(credential);
        const row = await clientRow(input.clientId);
        if (row.tenantId !== input.tenantId)
          throw new IamError('NOT_FOUND', 'Client not found.', 404);
        await tx.put('oauthClients', { ...row, revoked: true, updatedAt: Date.now() });
        await purgeClientArtifacts(tx, input.clientId);
        await audit(
          tx,
          input.tenantId,
          principal.identity.id,
          'iam:oauth:RevokeClient',
          input.clientId,
        );
      });
    },
    /**
     * Connected apps: the live consents an account gave. Without `identityId`, the caller's own grants; other
     * accounts need `iam:oauth:grants:read` on `iam/{identityId}`.
     */
    async listGrants(
      credential: CredentialInput,
      input: { tenantId: string; identityId?: string; clientId?: string },
    ): Promise<OAuthGrantSummary[]> {
      const owner = await grantOwner(
        credential,
        input.tenantId,
        input.identityId,
        'iam:oauth:grants:read',
      );
      return (await accountGrants(input.tenantId, owner.identityId))
        .map((grant) => grant.summary)
        .filter((grant) => !input.clientId || grant.clientId === input.clientId);
    },
    /** Revokes one consent by its `OAuthGrantSummary.id`, with every token and code issued under it. */
    async revokeGrant(
      credential: CredentialInput,
      input: { tenantId: string; grantId: string },
    ): Promise<void> {
      const row =
        typeof input.grantId === 'string' && /^[0-9a-f]{64}$/.test(input.grantId)
          ? await config.store.get<Artifact>('oauthArtifacts', input.grantId)
          : undefined;
      const principal = await config.authenticate(credential);
      const identityId =
        row?.model === 'Grant' && row.boundTenantId === input.tenantId ? row.accountId : undefined;
      // Unknown references and foreign grants look the same; authorization runs before disclosure.
      const owner = await grantOwner(
        credential,
        input.tenantId,
        identityId ?? principal.identity.id,
        'iam:oauth:grants:revoke',
      );
      const grant = identityId
        ? (await accountGrants(input.tenantId, owner.identityId)).find(
            (candidate) => candidate.row.id === input.grantId,
          )
        : undefined;
      if (!grant) throw new IamError('NOT_FOUND', 'Grant not found.', 404);
      await revokeGrantIds(owner.principal, input.tenantId, [grant]);
    },
    /**
     * Disconnects apps: revokes every consent of an account, optionally only for one client. Returns the number
     * of revoked grants.
     */
    async revokeGrants(
      credential: CredentialInput,
      input: { tenantId: string; identityId?: string; clientId?: string },
    ): Promise<{ revoked: number }> {
      const owner = await grantOwner(
        credential,
        input.tenantId,
        input.identityId,
        'iam:oauth:grants:revoke',
      );
      const matching = (await accountGrants(input.tenantId, owner.identityId)).filter(
        (grant) => !input.clientId || grant.summary.clientId === input.clientId,
      );
      await revokeGrantIds(owner.principal, input.tenantId, matching);
      return { revoked: matching.length };
    },
    /**
     * OpenID back-channel logout for ended IAM sessions. Every consent bound to a session that expired, was revoked,
     * or whose account or tenant became unavailable is revoked with its tokens, and clients registered with a
     * `backchannelLogoutUri` receive a signed logout token for the account. Session expiry emits no event, so call
     * this on a schedule as well as after sign-out and deactivation events. Delivery failures are reported, not retried.
     */
    async logoutEndedSessions(input: { identityId?: string } = {}): Promise<{
      sessions: number;
      grants: number;
      notified: number;
      failures: { clientId: string; identityId: string }[];
    }> {
      const bindings = await config.store.find<GrantSession>(
        'oauthGrantSessions',
        input.identityId ? { identityId: input.identityId } : undefined,
      );
      const ended = new Map<string, GrantSession>();
      const sessionEnded = new Map<string, boolean>();
      for (const binding of bindings) {
        if (!sessionEnded.has(binding.sessionId)) {
          const session = await config.store.get<Session>('sessions', binding.sessionId);
          const identity = await config.store.get<Identity>('identities', binding.identityId);
          let live =
            !!session &&
            !!identity &&
            session.identityId === binding.identityId &&
            session.tenantId === binding.tenantId &&
            session.expiresAt > Date.now() &&
            identity.status === 'active' &&
            (await tenantTreeActive(config.store, binding.tenantId));
          if (live && config.validateSession)
            live = await config.validateSession(binding.sessionId).then(
              () => true,
              () => false,
            );
          sessionEnded.set(binding.sessionId, !live);
        }
        if (sessionEnded.get(binding.sessionId)) ended.set(binding.id, binding);
      }
      if (!ended.size) return { sessions: 0, grants: 0, notified: 0, failures: [] };
      // Grant artifacts are keyed by their own hash; match them to bindings through the sealed grant ID.
      const revoked: { grantId: string; clientId: string; binding: GrantSession }[] = [];
      for (const identityId of new Set([...ended.values()].map((binding) => binding.identityId)))
        for (const row of await config.store.find<Artifact>('oauthArtifacts', {
          model: 'Grant',
          accountId: identityId,
        })) {
          const { jti } = crypt.open<{ jti?: string }>(row.encrypted);
          const binding = jti ? ended.get(hash(jti)) : undefined;
          if (binding && row.clientId)
            revoked.push({ grantId: jti!, clientId: row.clientId, binding });
        }
      let notified = 0;
      const failures: { clientId: string; identityId: string }[] = [];
      const informed = new Set<string>();
      for (const grant of revoked) {
        const key = `${grant.clientId}\n${grant.binding.identityId}`;
        if (informed.has(key)) continue;
        informed.add(key);
        const client = await provider.Client.find(grant.clientId).catch(() => undefined);
        if (!client?.backchannelLogoutUri) continue;
        try {
          // oidc-provider signs the logout token with the provider keys and POSTs it to the client.
          await (
            client as unknown as { backchannelLogout(sub: string, sid: string): Promise<void> }
          ).backchannelLogout(grant.binding.identityId, '');
          notified++;
        } catch {
          failures.push({ clientId: grant.clientId, identityId: grant.binding.identityId });
        }
      }
      for (const grant of revoked) await grants.revokeByGrantId(grant.grantId);
      await config.store.transaction(async (tx) => {
        for (const binding of ended.values()) await tx.delete('oauthGrantSessions', binding.id);
        for (const key of informed) {
          const [clientId, identityId] = key.split('\n') as [string, string];
          const binding = [...ended.values()].find((value) => value.identityId === identityId)!;
          await audit(tx, binding.tenantId, identityId, 'iam:oauth:SessionLogout', clientId);
        }
      });
      return {
        sessions: new Set([...ended.values()].map((binding) => binding.sessionId)).size,
        grants: revoked.length,
        notified,
        failures,
      };
    },
    /** The immutable tenant/client binding of a pending interaction, for the application's login and consent page. */
    async interactionDetails(req: IncomingMessage, res: ServerResponse) {
      const details = await provider.interactionDetails(req, res);
      const row = await clientRow(String(details.params.client_id));
      const resource = details.params.resource;
      return {
        uid: details.uid,
        prompt: details.prompt.name,
        tenantId: row.tenantId,
        clientId: row.clientId,
        clientName: summary(row).name,
        /** Branding for the consent screen, and whether the host may approve it without asking. */
        client: (({ name, logoUri, clientUri, policyUri, tosUri, firstParty }) => ({
          name,
          ...(logoUri ? { logoUri } : {}),
          ...(clientUri ? { clientUri } : {}),
          ...(policyUri ? { policyUri } : {}),
          ...(tosUri ? { tosUri } : {}),
          firstParty,
        }))(summary(row)),
        scopes: typeof details.params.scope === 'string' ? details.params.scope.split(' ') : [],
        resources: (Array.isArray(resource) ? resource : resource ? [resource] : []).map(String),
        details: details.prompt.details,
      };
    },
    /** The caller supplies an actual IAM credential. No accountId or tenant is accepted from form data. */
    async completeInteraction(
      req: IncomingMessage,
      res: ServerResponse,
      input: { credential: CredentialInput; consent: boolean },
    ) {
      if (
        req.method !== 'POST' ||
        !req.headers.origin ||
        !config.trustedOrigins.includes(req.headers.origin)
      )
        throw new IamError('CSRF', 'A trusted Origin is required.', 403);
      return config.store.transaction(async (tx) => {
        const principal = await config.authenticate(input.credential);
        if (principal.session.kind !== 'user')
          throw new IamError('INVALID_SESSION', 'A user session is required.', 403);
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Consent cannot be granted while impersonating a member.',
            403,
          );
        const details = await provider.interactionDetails(req, res);
        const client = await clientRow(String(details.params.client_id));
        if (client.tenantId !== principal.identity.tenantId)
          throw new IamError(
            'TENANT_MISMATCH',
            'Sign in to the client tenant before continuing.',
            403,
          );
        if (!input.consent)
          return provider.interactionFinished(
            req,
            res,
            { error: 'access_denied', error_description: 'Consent denied.' },
            { mergeWithLastSubmission: false },
          );
        // Extend the account's existing consent for this client instead of accumulating grants.
        const existing = details.grantId ? await provider.Grant.find(details.grantId) : undefined;
        const grant =
          existing &&
          existing.accountId === principal.identity.id &&
          existing.clientId === client.clientId
            ? existing
            : new provider.Grant({ accountId: principal.identity.id, clientId: client.clientId });
        grant.addOIDCScope(String(details.params.scope ?? 'openid'));
        const missingClaims = details.prompt.details.missingOIDCClaims;
        if (Array.isArray(missingClaims))
          grant.addOIDCClaims(
            missingClaims.filter((value): value is string => typeof value === 'string'),
          );
        // Requested resources receive the requested scopes their resource server defines (also under forced consent,
        // where the prompt details list nothing missing).
        const requestedScopes = String(details.params.scope ?? '').split(' ');
        const requestedResources = details.params.resource;
        for (const indicator of (Array.isArray(requestedResources)
          ? requestedResources
          : requestedResources
            ? [requestedResources]
            : []
        ).map(String)) {
          const server = resourceServers.get(indicator);
          const scopes = server?.scopes.filter((scope) => requestedScopes.includes(scope)) ?? [];
          if (server && client.resources?.includes(indicator) && scopes.length)
            grant.addResourceScope(indicator, scopes);
        }
        const missingResourceScopes = details.prompt.details.missingResourceScopes;
        if (missingResourceScopes && typeof missingResourceScopes === 'object')
          for (const [indicator, scopes] of Object.entries(missingResourceScopes))
            if (Array.isArray(scopes))
              grant.addResourceScope(
                indicator,
                scopes.filter((value): value is string => typeof value === 'string'),
              );
        const grantId = await grant.save();
        const binding: GrantSession = {
          id: hash(grantId),
          tenantId: principal.identity.tenantId,
          sessionId: principal.session.id,
          identityId: principal.identity.id,
        };
        if (await tx.get('oauthGrantSessions', binding.id))
          await tx.put('oauthGrantSessions', binding);
        else await tx.insert<GrantSession>('oauthGrantSessions', binding);
        await audit(
          tx,
          principal.identity.tenantId,
          principal.identity.id,
          'iam:oauth:Consent',
          client.clientId,
        );
        await provider.interactionFinished(
          req,
          res,
          {
            login: {
              accountId: principal.identity.id,
              ts: Math.floor(principal.session.authenticatedAt / 1000),
              amr: principal.session.mfa ? ['pwd', 'mfa'] : ['pwd'],
            },
            consent: { grantId },
          },
          { mergeWithLastSubmission: false },
        );
      });
    },
  };
}

export type OAuthProviderService = ReturnType<typeof createOAuthProvider>;
