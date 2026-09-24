import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import * as oauth from 'oauth4webapi';
import {
  IamError,
  tenantTreeActive,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type StoredRecord,
} from '@better-iam/core';

export interface FederatedIdentity {
  tenantId: string;
  providerId: string;
  issuer: string;
  subject: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  linkingSessionId?: string;
  linkingIdentityId?: string;
  /** Identity attributes mapped from the provider's verified claims or profile; validated by the host. */
  attributes?: Record<string, unknown>;
}
export interface OAuthLoginConnection {
  id: string;
  tenantId: string;
  kind: 'oidc' | 'oauth2' | 'google' | 'github' | 'microsoft';
  clientId: string;
  clientSecret?: string;
  /** Fixed, registered callback URL. Never supplied by the browser. */
  redirectUri: string;
  issuer?: string;
  scopes?: string[];
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  /**
   * Microsoft Entra ID: the directory to sign in against, `organizations` (default, any work or school tenant),
   * `common`, `consumers`, or one tenant ID or domain. `issuer` may name a sovereign-cloud authority
   * (default `https://login.microsoftonline.com`).
   */
  microsoftTenant?: string;
  /**
   * Entra tenant IDs (`tid`) accepted by a multi-tenant Microsoft connection. Required unless `microsoftTenant` names
   * a single tenant, so that an arbitrary organization's directory cannot sign in to this tenant.
   */
  allowedMicrosoftTenants?: string[];
  /**
   * Email domains whose verified addresses may enroll: a first sign-in from any other address creates no account (it
   * can still sign in to an account linked before). Without it, any verified address the provider vouches for enrolls
   * in `tenantId` on first sign-in — for Google or GitHub, that is anyone with an account there.
   */
  allowedEmailDomains?: string[];
  /** Generic OAuth2 has no standard identity schema; this trusted server mapper must select a stable provider ID. */
  mapProfile?(profile: Record<string, unknown>): {
    subject: string;
    email?: string;
    emailVerified?: boolean;
    name?: string;
  };
  /**
   * Maps the provider's verified ID token claims (OIDC, Google) or profile (GitHub, OAuth2) to identity attributes
   * declared by the product; they are validated and stored on every sign-in. Return undefined to leave them untouched.
   */
  mapAttributes?(claims: Record<string, unknown>): Record<string, unknown> | undefined;
}
export interface OAuthLoginConfig {
  store: IamStore;
  connections: OAuthLoginConnection[];
  completeAuthentication(identity: FederatedIdentity): Promise<unknown>;
  authenticate?(credential: CredentialInput): Promise<AuthenticatedPrincipal>;
  trustedOrigins?: string[];
  basePath?: string;
  /** Test-only/local development; production requires HTTPS everywhere. */
  allowInsecureLocalhost?: boolean;
}
/** Optional hints forwarded to the identity provider's sign-in page (for example from home-realm discovery). */
export interface LoginHints {
  /** Pre-fills the account, usually an email address (GitHub: the username). */
  loginHint?: string;
  /** Microsoft `domain_hint` or Google `hd`: skips the provider's account picker for that organization domain. */
  domainHint?: string;
  /** `login` forces re-authentication, `select_account` shows the picker, `consent` re-asks consent. */
  prompt?: 'login' | 'select_account' | 'consent' | 'none';
}
interface LoginState extends StoredRecord {
  connectionId: string;
  state: string;
  bindingHash: string;
  codeVerifier: string;
  nonce: string;
  expiresAt: number;
  linkingSessionId?: string;
  linkingIdentityId?: string;
}
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const multiTenantDirectories = ['common', 'organizations', 'consumers'];
const MICROSOFT_AUTHORITY = 'https://login.microsoftonline.com';

function url(value: string, allowLocalhost: boolean): URL {
  const parsed = new URL(value);
  if (
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    (parsed.protocol !== 'https:' &&
      !(
        allowLocalhost &&
        parsed.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)
      ))
  )
    throw new IamError(
      'configuration',
      'OAuth endpoints require HTTPS (or explicitly enabled localhost HTTP).',
    );
  return parsed;
}
async function activeTenant(store: IamStore, id: string): Promise<void> {
  if (!(await tenantTreeActive(store, id)))
    throw new IamError('TENANT_INACTIVE', 'Tenant is unavailable.', 403);
}

/** OAuth/OIDC relying-party flows. Login state is single-use, browser-bound and tenant-bound. */
export function createOAuthLogin(config: OAuthLoginConfig) {
  const basePath = (config.basePath ?? '/oauth/login').replace(/\/$/, '');
  const connections = new Map<string, OAuthLoginConnection>();
  for (const connection of config.connections) {
    if (
      !connection.id ||
      connections.has(connection.id) ||
      !connection.tenantId ||
      !connection.clientId
    )
      throw new IamError(
        'configuration',
        'OAuth connection IDs must be unique and configuration complete.',
      );
    url(connection.redirectUri, !!config.allowInsecureLocalhost);
    if (['oidc', 'oauth2'].includes(connection.kind) && !connection.issuer)
      throw new IamError('configuration', 'The provider issuer is required.');
    if (
      connection.allowedEmailDomains !== undefined &&
      (!Array.isArray(connection.allowedEmailDomains) ||
        !connection.allowedEmailDomains.length ||
        connection.allowedEmailDomains.some(
          (domain) =>
            typeof domain !== 'string' || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(domain),
        ))
    )
      throw new IamError(
        'configuration',
        'allowedEmailDomains must list one or more exact domain names.',
      );
    if (connection.issuer) url(connection.issuer, !!config.allowInsecureLocalhost);
    if (connection.kind === 'microsoft') {
      const directory = connection.microsoftTenant ?? 'organizations';
      if (!/^[A-Za-z0-9.-]{1,128}$/.test(directory))
        throw new IamError(
          'configuration',
          'microsoftTenant must be a tenant ID, domain, or alias.',
        );
      if (
        multiTenantDirectories.includes(directory.toLowerCase()) &&
        !connection.allowedMicrosoftTenants?.length
      )
        throw new IamError(
          'configuration',
          'Multi-tenant Microsoft connections need allowedMicrosoftTenants.',
        );
    }
    if (connection.kind === 'github' && !connection.clientSecret)
      throw new IamError('configuration', 'GitHub client secret is required.');
    if ([...connections.values()].some((value) => value.redirectUri === connection.redirectUri))
      throw new IamError('configuration', 'OAuth callback URLs must be unique per connection.');
    if (connection.kind === 'oauth2') {
      if (
        !connection.authorizationEndpoint ||
        !connection.tokenEndpoint ||
        !connection.userInfoEndpoint ||
        !connection.mapProfile
      )
        throw new IamError(
          'configuration',
          'Generic OAuth2 requires authorization/token/profile endpoints and a trusted profile mapper.',
        );
      for (const endpoint of [
        connection.authorizationEndpoint,
        connection.tokenEndpoint,
        connection.userInfoEndpoint,
      ])
        url(endpoint, !!config.allowInsecureLocalhost);
    }
    connections.set(connection.id, { ...connection });
  }
  function connection(id: string) {
    const found = connections.get(id);
    if (!found) throw new IamError('NOT_FOUND', 'OAuth connection not found.', 404);
    return found;
  }
  const options = config.allowInsecureLocalhost ? { [oauth.allowInsecureRequests]: true } : {};
  /**
   * Entra ID discovery. Multi-tenant documents name their issuer `…/{tenantid}/v2.0`, which generic discovery rejects,
   * so the document is checked here: every endpoint must live on the configured authority.
   */
  async function microsoftMetadata(item: OAuthLoginConnection): Promise<oauth.AuthorizationServer> {
    const authority = url(item.issuer ?? MICROSOFT_AUTHORITY, !!config.allowInsecureLocalhost);
    const root = `${authority.origin}${authority.pathname.replace(/\/$/, '')}`;
    const directory = encodeURIComponent(item.microsoftTenant ?? 'organizations');
    let document: oauth.AuthorizationServer;
    try {
      const response = await fetch(`${root}/${directory}/v2.0/.well-known/openid-configuration`, {
        headers: { accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error(String(response.status));
      document = (await response.json()) as oauth.AuthorizationServer;
    } catch {
      throw new IamError('OAUTH_DISCOVERY', 'Microsoft discovery failed.', 502);
    }
    const issuer = typeof document.issuer === 'string' ? document.issuer : '';
    if (!issuer.startsWith(`${root}/`) || !issuer.endsWith('/v2.0'))
      throw new IamError('OAUTH_DISCOVERY', 'Unexpected Microsoft issuer.', 502);
    for (const endpoint of [
      document.authorization_endpoint,
      document.token_endpoint,
      document.jwks_uri,
    ]) {
      if (!endpoint)
        throw new IamError('OAUTH_DISCOVERY', 'Microsoft metadata is incomplete.', 502);
      if (url(endpoint, !!config.allowInsecureLocalhost).origin !== authority.origin)
        throw new IamError('OAUTH_DISCOVERY', 'Microsoft endpoints must use the authority.', 502);
    }
    return document;
  }
  /** The concrete issuer of the directory that signed in, after checking it against `allowedMicrosoftTenants`. */
  async function microsoftIssuer(
    item: OAuthLoginConnection,
    discovered: oauth.AuthorizationServer,
    tokenResponse: Response,
  ): Promise<oauth.AuthorizationServer> {
    let tid: unknown;
    try {
      const body = (await tokenResponse.clone().json()) as { id_token?: unknown };
      const payload = String(body.id_token).split('.')[1]!;
      tid = (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { tid?: unknown })
        .tid;
    } catch {
      tid = undefined;
    }
    if (
      typeof tid !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tid)
    )
      throw new IamError('OAUTH_PROFILE', 'The Microsoft ID token names no directory.', 401);
    if (
      item.allowedMicrosoftTenants?.length &&
      !item.allowedMicrosoftTenants.some((allowed) => allowed.toLowerCase() === tid.toLowerCase())
    )
      throw new IamError('OAUTH_TENANT', 'This Microsoft directory may not sign in here.', 403);
    // A single-tenant document already names its issuer; the ID token check compares against it.
    return discovered.issuer.includes('{tenantid}')
      ? { ...discovered, issuer: discovered.issuer.replace('{tenantid}', tid) }
      : discovered;
  }
  async function metadata(item: OAuthLoginConnection): Promise<oauth.AuthorizationServer> {
    if (item.kind === 'github')
      return {
        issuer: 'https://github.com',
        authorization_endpoint: 'https://github.com/login/oauth/authorize',
        token_endpoint: 'https://github.com/login/oauth/access_token',
      };
    if (item.kind === 'oauth2')
      return {
        issuer: item.issuer!,
        authorization_endpoint: item.authorizationEndpoint!,
        token_endpoint: item.tokenEndpoint!,
        userinfo_endpoint: item.userInfoEndpoint!,
      };
    if (item.kind === 'microsoft') return microsoftMetadata(item);
    const issuer = url(
      item.kind === 'google' ? 'https://accounts.google.com' : item.issuer!,
      !!config.allowInsecureLocalhost,
    );
    const result = await oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, options),
    );
    for (const endpoint of [
      result.authorization_endpoint,
      result.token_endpoint,
      result.jwks_uri,
      result.userinfo_endpoint,
    ])
      if (endpoint) url(endpoint, !!config.allowInsecureLocalhost);
    return result;
  }
  /** Validated sign-in hints: never trusted for identity, only forwarded to the provider's login screen. */
  function hints(input: LoginHints = {}): LoginHints {
    const result: LoginHints = {};
    if (input.loginHint !== undefined) {
      if (
        typeof input.loginHint !== 'string' ||
        !input.loginHint ||
        input.loginHint.length > 320 ||
        /[\s<>]/.test(input.loginHint)
      )
        throw new IamError(
          'INVALID_INPUT',
          'login_hint must be a short identifier such as an email address.',
          400,
        );
      result.loginHint = input.loginHint;
    }
    if (input.domainHint !== undefined) {
      if (
        typeof input.domainHint !== 'string' ||
        !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i.test(input.domainHint)
      )
        throw new IamError('INVALID_INPUT', 'domain_hint must be a domain name.', 400);
      result.domainHint = input.domainHint;
    }
    if (input.prompt !== undefined) {
      if (!['login', 'select_account', 'consent', 'none'].includes(input.prompt))
        throw new IamError(
          'INVALID_INPUT',
          'prompt must be login, select_account, consent, or none.',
          400,
        );
      result.prompt = input.prompt;
    }
    return result;
  }
  async function begin(
    connectionId: string,
    linkingCredential?: CredentialInput,
    loginHints?: LoginHints,
  ) {
    const requested = hints(loginHints);
    const item = connection(connectionId);
    await activeTenant(config.store, item.tenantId);
    let linkingSessionId: string | undefined;
    let linkingIdentityId: string | undefined;
    if (linkingCredential) {
      if (!config.authenticate)
        throw new IamError('configuration', 'Linking requires an authenticate callback.');
      const principal = await config.authenticate(linkingCredential);
      const age = Date.now() - principal.session.authenticatedAt;
      if (
        principal.identity.tenantId !== item.tenantId ||
        principal.identity.rootAdmin ||
        principal.session.kind !== 'user' ||
        age < 0 ||
        age > 300_000
      )
        throw new IamError(
          'RECENT_AUTH_REQUIRED',
          'Linking requires recent authentication to a non-root identity in this tenant.',
          403,
        );
      linkingSessionId = principal.session.id;
      linkingIdentityId = principal.identity.id;
    }
    const as = await metadata(item);
    if (!as.authorization_endpoint)
      throw new IamError('configuration', 'Authorization endpoint is missing.');
    const state = oauth.generateRandomState();
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const nonce = oauth.generateRandomNonce();
    const binding = randomBytes(32).toString('base64url');
    const authorizationUrl = new URL(as.authorization_endpoint);
    authorizationUrl.searchParams.set('client_id', item.clientId);
    authorizationUrl.searchParams.set('redirect_uri', item.redirectUri);
    authorizationUrl.searchParams.set('response_type', 'code');
    const scopes =
      item.scopes ??
      (item.kind === 'github'
        ? ['read:user', 'user:email']
        : item.kind === 'oauth2'
          ? []
          : ['openid', 'email', 'profile']);
    if (scopes.length) authorizationUrl.searchParams.set('scope', scopes.join(' '));
    if (requested.loginHint && item.kind !== 'github')
      authorizationUrl.searchParams.set('login_hint', requested.loginHint);
    if (requested.loginHint && item.kind === 'github')
      authorizationUrl.searchParams.set('login', requested.loginHint);
    if (requested.domainHint && item.kind === 'microsoft')
      authorizationUrl.searchParams.set('domain_hint', requested.domainHint);
    if (requested.domainHint && item.kind === 'google')
      authorizationUrl.searchParams.set('hd', requested.domainHint);
    if (requested.prompt && item.kind !== 'github')
      authorizationUrl.searchParams.set('prompt', requested.prompt);
    authorizationUrl.searchParams.set('state', state);
    authorizationUrl.searchParams.set(
      'code_challenge',
      await oauth.calculatePKCECodeChallenge(codeVerifier),
    );
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    if (item.kind === 'oidc' || item.kind === 'google' || item.kind === 'microsoft')
      authorizationUrl.searchParams.set('nonce', nonce);
    await config.store.transaction(async (tx) => {
      await activeTenant(tx, item.tenantId);
      await tx.insert<LoginState>('oauthLoginStates', {
        id: hash(state),
        tenantId: item.tenantId,
        connectionId,
        state,
        codeVerifier,
        nonce,
        bindingHash: hash(binding),
        expiresAt: Date.now() + 600_000,
        linkingIdentityId,
        linkingSessionId,
      });
    });
    return { url: authorizationUrl.href, binding, state, expiresAt: Date.now() + 600_000 };
  }
  async function callback(connectionId: string, callbackUrl: string, binding: string) {
    const item = connection(connectionId);
    const returned = new URL(callbackUrl);
    const expected = new URL(item.redirectUri);
    if (returned.origin !== expected.origin || returned.pathname !== expected.pathname)
      throw new IamError('OAUTH_CALLBACK', 'Unexpected callback URL.', 400);
    const stateValue = returned.searchParams.get('state');
    if (!stateValue || stateValue.length > 512 || !binding)
      throw new IamError('OAUTH_STATE', 'Missing login state.', 400);
    const saved = await config.store.transaction(async (tx) => {
      const state = await tx.get<LoginState>('oauthLoginStates', hash(stateValue));
      if (
        !state ||
        state.connectionId !== connectionId ||
        state.tenantId !== item.tenantId ||
        state.expiresAt <= Date.now() ||
        !timingSafeEqual(Buffer.from(hash(binding)), Buffer.from(state.bindingHash))
      )
        throw new IamError('OAUTH_STATE', 'Invalid, expired, or replayed login state.', 400);
      await activeTenant(tx, item.tenantId);
      await tx.delete('oauthLoginStates', state.id);
      return state;
    });
    const discovered = await metadata(item);
    const client: oauth.Client = { client_id: item.clientId };
    const params = oauth.validateAuthResponse(
      item.kind === 'microsoft'
        ? { ...discovered, authorization_response_iss_parameter_supported: false }
        : discovered,
      client,
      returned,
      saved.state,
    );
    const clientAuth = item.clientSecret ? oauth.ClientSecretPost(item.clientSecret) : oauth.None();
    const tokenResponse = await oauth.authorizationCodeGrantRequest(
      discovered,
      client,
      clientAuth,
      params,
      item.redirectUri,
      saved.codeVerifier,
      { ...options, headers: { accept: 'application/json' } },
    );
    // Entra multi-tenant metadata names the issuer as a template; resolve it for the directory that signed in.
    const as =
      item.kind === 'microsoft'
        ? await microsoftIssuer(item, discovered, tokenResponse)
        : discovered;
    const result = await oauth.processAuthorizationCodeResponse(
      as,
      client,
      tokenResponse,
      item.kind === 'github' || item.kind === 'oauth2'
        ? {}
        : { expectedNonce: saved.nonce, requireIdToken: true },
    );
    let identity: FederatedIdentity;
    if (item.kind === 'github') {
      const profileResponse = await oauth.protectedResourceRequest(
        result.access_token,
        'GET',
        new URL('https://api.github.com/user'),
        new Headers({ accept: 'application/vnd.github+json', 'user-agent': 'better-iam' }),
      );
      if (!profileResponse.ok)
        throw new IamError('OAUTH_PROFILE', 'Provider profile request failed.', 401);
      const profile = (await profileResponse.json()) as Record<string, unknown>;
      if ((typeof profile.id !== 'number' && typeof profile.id !== 'string') || !String(profile.id))
        throw new IamError('OAUTH_PROFILE', 'Provider subject is missing.', 401);
      identity = {
        tenantId: item.tenantId,
        providerId: item.id,
        issuer: 'https://github.com',
        subject: String(profile.id),
        name:
          typeof profile.name === 'string'
            ? profile.name
            : typeof profile.login === 'string'
              ? profile.login
              : undefined,
      };
      const attributes = item.mapAttributes?.(profile);
      if (attributes !== undefined) identity.attributes = attributes;
      const emailResponse = await oauth.protectedResourceRequest(
        result.access_token,
        'GET',
        new URL('https://api.github.com/user/emails'),
        new Headers({ accept: 'application/vnd.github+json', 'user-agent': 'better-iam' }),
      );
      if (emailResponse.ok) {
        const emails = (await emailResponse.json()) as unknown;
        if (Array.isArray(emails)) {
          const primary = emails.find(
            (value: unknown) =>
              value &&
              typeof value === 'object' &&
              'primary' in value &&
              value.primary === true &&
              'verified' in value &&
              value.verified === true,
          ) as Record<string, unknown> | undefined;
          if (primary && typeof primary.email === 'string') {
            identity.email = primary.email;
            identity.emailVerified = true;
          }
        }
      }
    } else if (item.kind === 'oauth2') {
      const profileResponse = await oauth.protectedResourceRequest(
        result.access_token,
        'GET',
        new URL(item.userInfoEndpoint!),
        new Headers({ accept: 'application/json' }),
        undefined,
        options,
      );
      if (!profileResponse.ok)
        throw new IamError('OAUTH_PROFILE', 'Provider profile request failed.', 401);
      const profile = (await profileResponse.json()) as unknown;
      if (!profile || typeof profile !== 'object' || Array.isArray(profile))
        throw new IamError('OAUTH_PROFILE', 'Provider profile is invalid.', 401);
      const mapped = item.mapProfile!(profile as Record<string, unknown>);
      if (typeof mapped.subject !== 'string' || !mapped.subject || mapped.subject.length > 512)
        throw new IamError('OAUTH_PROFILE', 'Provider subject is missing.', 401);
      identity = {
        tenantId: item.tenantId,
        providerId: item.id,
        issuer: item.issuer!,
        subject: mapped.subject,
        email: mapped.email,
        emailVerified: mapped.emailVerified === true,
        name: mapped.name,
      };
      const attributes = item.mapAttributes?.(profile as Record<string, unknown>);
      if (attributes !== undefined) identity.attributes = attributes;
    } else {
      await oauth.validateApplicationLevelSignature(as, tokenResponse, options);
      const claims = oauth.getValidatedIdTokenClaims(result);
      if (!claims?.sub) throw new IamError('OAUTH_PROFILE', 'OIDC subject is missing.', 401);
      identity = {
        tenantId: item.tenantId,
        providerId: item.id,
        issuer: claims.iss,
        subject: claims.sub,
        email: typeof claims.email === 'string' ? claims.email : undefined,
        // Entra lets directory administrators set any email; only its verified-domain claim (xms_edov) counts.
        emailVerified:
          item.kind === 'microsoft' ? claims.xms_edov === true : claims.email_verified === true,
        name: typeof claims.name === 'string' ? claims.name : undefined,
      };
      const attributes = item.mapAttributes?.(claims as Record<string, unknown>);
      if (attributes !== undefined) identity.attributes = attributes;
    }
    await activeTenant(config.store, item.tenantId);
    // Addresses outside the connection's enrollment domains never create an account (no verified email to enroll with).
    if (
      item.allowedEmailDomains &&
      identity.emailVerified &&
      !item.allowedEmailDomains.some(
        (domain) => identity.email?.toLowerCase().endsWith(`@${domain.toLowerCase()}`) === true,
      )
    )
      identity.emailVerified = false;
    if (saved.linkingSessionId && saved.linkingIdentityId) {
      identity.linkingIdentityId = saved.linkingIdentityId;
      identity.linkingSessionId = saved.linkingSessionId;
    }
    // Only protocol-verified claims reach this trusted server callback. It must apply local MFA.
    return config.completeAuthentication(identity);
  }
  return {
    begin,
    callback,
    basePath,
    async handler(request: Request): Promise<Response | undefined> {
      const requestUrl = new URL(request.url);
      const item = [...connections.values()].find((value) => {
        const target = new URL(value.redirectUri);
        return target.origin === requestUrl.origin && target.pathname === requestUrl.pathname;
      });
      if (request.method === 'GET' && item) {
        try {
          const secure = new URL(item.redirectUri).protocol === 'https:';
          const cookieName = `${secure ? '__Host-' : ''}better-iam-oauth-${hash(item.id).slice(0, 12)}`;
          const binding =
            request.headers
              .get('cookie')
              ?.split(';')
              .map((v) => v.trim())
              .find((v) => v.startsWith(`${cookieName}=`))
              ?.slice(cookieName.length + 1) ?? '';
          const result = await callback(item.id, request.url, binding);
          return Response.json(result, {
            headers: {
              'cache-control': 'no-store',
              'set-cookie': `${cookieName}=; Path=/; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=Lax; Max-Age=0`,
            },
          });
        } catch (error) {
          return Response.json(
            { error: error instanceof IamError ? error.code : 'OAUTH_FAILED' },
            {
              status: error instanceof IamError ? error.status : 401,
              headers: { 'cache-control': 'no-store' },
            },
          );
        }
      }
      if (!requestUrl.pathname.startsWith(`${basePath}/`)) return undefined;
      if (!['GET', 'POST'].includes(request.method))
        return Response.json({ error: 'METHOD_NOT_ALLOWED' }, { status: 405 });
      try {
        const id = decodeURIComponent(requestUrl.pathname.slice(basePath.length + 1));
        if (request.method === 'POST') {
          const item = connection(id);
          const origin = request.headers.get('origin');
          if (
            !origin ||
            !(config.trustedOrigins ?? [new URL(item.redirectUri).origin]).includes(origin) ||
            request.headers.get('x-better-iam') !== '1' ||
            !request.headers.get('content-type')?.startsWith('application/json')
          )
            throw new IamError(
              'CSRF',
              'Linking requires a trusted Origin and X-Better-IAM header.',
              403,
            );
        }
        const query = requestUrl.searchParams;
        const result = await begin(
          id,
          request.method === 'POST' ? { headers: request.headers } : undefined,
          {
            ...(query.get('login_hint') ? { loginHint: query.get('login_hint')! } : {}),
            ...(query.get('domain_hint') ? { domainHint: query.get('domain_hint')! } : {}),
            ...(query.get('prompt') ? { prompt: query.get('prompt') as LoginHints['prompt'] } : {}),
          },
        );
        const secure = new URL(connection(id).redirectUri).protocol === 'https:';
        const headers = {
          'cache-control': 'no-store',
          'set-cookie': `${secure ? '__Host-' : ''}better-iam-oauth-${hash(id).slice(0, 12)}=${result.binding}; Path=/; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=Lax; Max-Age=600`,
        };
        return request.method === 'POST'
          ? Response.json({ url: result.url }, { headers })
          : new Response(null, { status: 302, headers: { ...headers, location: result.url } });
      } catch (error) {
        return Response.json(
          { error: error instanceof IamError ? error.code : 'OAUTH_FAILED' },
          { status: error instanceof IamError ? error.status : 401 },
        );
      }
    },
  };
}

export type OAuthLoginService = ReturnType<typeof createOAuthLogin>;
