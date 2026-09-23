import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  IamError,
  type CredentialInput,
  type OutboxMessage,
  type Session,
  type SessionClientInfo,
} from '@better-iam/core';
import type { AuthService } from '@better-iam/auth';
import { clientFromRequest } from './client-info.js';
import type { ServerContext } from './context.js';
import { normalizeHost, WrongRegionError } from './hosts.js';
import type { MetricsCollector } from './metrics.js';
import { deniedStatuses, type Observer } from './observe.js';
import type { AuthorizationCheck } from './options.js';
import { object, text } from './validation.js';

// HTTP endpoints are mapped explicitly: infrastructure helpers are never remotely callable.
export const publicAuthMethods = new Set([
  'signUp',
  'signIn',
  'requestEmailVerification',
  'verifyEmail',
  'requestPasswordReset',
  'resetPassword',
  'confirmEmailChange',
  'startPasswordless',
  'finishPasswordless',
  'beginMfa',
  'confirmMfa',
  'verifyMfa',
  'requestMfaCode',
  'recoverMfa',
  'beginPasskeyAuthentication',
  'finishPasskeyAuthentication',
  'beginPasskeyMfa',
  'finishPasskeyMfa',
]);
export const authenticatedAuthMethods = new Set([
  'signOut',
  'getSession',
  'listSessions',
  'revokeSession',
  'revokeOtherSessions',
  'changePassword',
  'requestEmailChange',
  'beginPasskeyRegistration',
  'finishPasskeyRegistration',
  'startPhoneVerification',
  'confirmPhoneVerification',
  'reauthenticate',
  'listPasskeys',
  'deletePasskey',
  'renamePasskey',
  'regenerateRecoveryCodes',
  'disableMfa',
  'listTrustedDevices',
  'revokeTrustedDevice',
  'revokeTrustedDevices',
  'listSecurityEvents',
  'mfaStatus',
]);
export const routeGroups = new Set([
  'tenants',
  'identities',
  'policies',
  'roles',
  'bindings',
  'authorities',
  'groups',
  'actions',
  'resourceTypes',
  'resources',
  'serviceAccounts',
  'credentials',
  'trust',
  'links',
  'root',
  'audit',
  'accessRequests',
  'webhooks',
  'relationships',
  'assertions',
  'domains',
  'config',
  'analysis',
  'certifications',
  'sod',
  'reports',
  'packages',
  'security',
  'roleMining',
  'impact',
  'invariants',
  'agreements',
  'accessPaths',
  'sts',
  'oidcProviders',
  'features',
  'onboarding',
  'hostnames',
  'agents',
  'delegations',
  'inference',
  'teams',
  'departments',
  'billing',
]);
export const publicApiMethods = new Set([
  'tenants/acceptInvitation',
  'tenants/lookup',
  'domains/discover',
  'identities/acceptInvitation',
  // The external OIDC token is the credential; the exchange is rate limited per trust before any lookup.
  'sts/assumeRoleWithWebIdentity',
]);
/**
 * Public routes that act in one organization named by `tenantId`: on an organization's own address they act in that
 * organization (the `tenantId` may be left out) and never another, and in a multi-region deployment they are served
 * only by the organization's home region. Every public `auth` method is tenant-bound too.
 */
const tenantBoundPublicMethods = new Set([
  'tenants/acceptInvitation',
  'identities/acceptInvitation',
  'sts/assumeRoleWithWebIdentity',
]);
/**
 * Routes whose session becomes the browser's session, so their answer sets the session cookie: sign-in ceremonies,
 * re-authentication, invitation acceptance, and switching to a linked account. Every other token stays in the body:
 * an assumed role (`roles/assume`) or an impersonation (`identities/impersonate`) replacing the caller's cookie
 * would strand the person's own session, which could then no longer be used or signed out from this browser.
 * Temporary credentials (`sts/*`) and OIDC provider management (`oidcProviders/*`) never set cookies: their tokens
 * are machine credentials returned once in the body, and cookies only ever carry user sessions.
 */
const sessionCookieRoutes = new Set([
  'auth/signIn',
  'auth/verifyMfa',
  'auth/confirmMfa',
  'auth/recoverMfa',
  'auth/finishPasswordless',
  'auth/finishPasskeyAuthentication',
  'auth/finishPasskeyMfa',
  'auth/reauthenticate',
  'tenants/acceptInvitation',
  'identities/acceptInvitation',
  'links/switch',
]);

type Callable = (...args: unknown[]) => Promise<unknown>;
type ApiSurface = Record<string, Record<string, Callable>>;

export interface ProtocolService {
  basePath: string;
  handler?(request: Request): Promise<Response | undefined>;
  nodeHandler?(req: IncomingMessage, res: ServerResponse): Promise<unknown> | unknown;
}

async function limitedBody(request: Request, limit: number): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) return '{}';
  let size = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    const item = await reader.read();
    if (item.done) break;
    size += item.value.length;
    if (size > limit) {
      await reader.cancel();
      throw new IamError('PAYLOAD_TOO_LARGE', 'Request body too large', 413);
    }
    chunks.push(item.value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Response headers every JSON answer carries: never cached, never sniffed, never leaking the URL as a referrer. */
const hardened = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};

/** A caller-supplied correlation ID (`X-Request-Id`), kept only when it is short and plain. */
function requestIdOf(request: Request): string | undefined {
  const value = request.headers.get('x-request-id');
  return value && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : undefined;
}

/** Sets headers on a response; one whose headers are immutable (a redirect, a fetched response) is copied first. */
function withHeaders(response: Response, extra: Record<string, string>): Response {
  const entries = Object.entries(extra);
  if (!entries.length) return response;
  try {
    for (const [key, value] of entries) response.headers.set(key, value);
    return response;
  } catch {
    const headers = new Headers(response.headers);
    for (const [key, value] of entries) headers.set(key, value);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }
}

/**
 * The JSON body of a successful call: a top-level `session` object loses `tokenHash` and `uniqueKey` (both equal the
 * token's hash), whatever the route returned. Defence in depth: issuers already return public projections.
 */
function publicResult(result: unknown): unknown {
  if (!result || typeof result !== 'object' || Array.isArray(result) || !('session' in result))
    return result;
  const session = (result as { session: unknown }).session;
  if (
    !session ||
    typeof session !== 'object' ||
    Array.isArray(session) ||
    !('tokenHash' in session || 'uniqueKey' in session)
  )
    return result;
  const {
    tokenHash: _tokenHash,
    uniqueKey: _uniqueKey,
    ...rest
  } = session as Record<string, unknown>;
  return { ...result, session: rest };
}

function withRequestId(response: Response, requestId: string | undefined): Response {
  return requestId ? withHeaders(response, { 'x-request-id': requestId }) : response;
}

function errorResponse(error: unknown): Response {
  const known = error instanceof IamError;
  const hint = known ? (error as unknown as { retryAfterMs?: unknown }).retryAfterMs : undefined;
  const retryAfterMs = typeof hint === 'number' && hint > 0 ? hint : undefined;
  const headers: Record<string, string> = { ...hardened };
  // Rate-limited callers learn when to come back (RFC 9110 Retry-After, in seconds).
  if (retryAfterMs !== undefined) headers['retry-after'] = String(Math.ceil(retryAfterMs / 1000));
  // A request for an organization another region serves learns where to go instead (`WRONG_REGION`).
  const redirect =
    error instanceof WrongRegionError
      ? { region: error.region, ...(error.location ? { location: error.location } : {}) }
      : {};
  return Response.json(
    {
      error: {
        code: known ? error.code : 'INTERNAL_ERROR',
        message: known ? error.message : 'Internal server error',
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
        ...redirect,
      },
    },
    { status: known ? error.status : 500, headers },
  );
}

/** Fetch and Node transports over the provisioning API, with the CSRF boundary, cookies, CORS, and protocol mounts. */
export function createHttp(
  ctx: ServerContext,
  api: object,
  authApi: object,
  extras: { metrics?: MetricsCollector; metricsToken?: string; metricsGauges?: boolean } = {},
) {
  const { config, auth, mountedProtocols, options, store } = ctx;
  const { baseURL, basePath, trustedOrigins } = config;
  const secure = baseURL.protocol === 'https:';
  const sameSite = options.http?.cookieSameSite ?? 'lax';
  if (sameSite !== 'lax' && sameSite !== 'strict')
    throw new IamError('INVALID_CONFIG', 'http.cookieSameSite must be lax or strict');
  if (
    options.http?.persistentCookies !== undefined &&
    typeof options.http.persistentCookies !== 'boolean'
  )
    throw new IamError('INVALID_CONFIG', 'http.persistentCookies must be a boolean');
  // Without a Max-Age the cookie lasts for the browser session only; the server session keeps its own lifetime.
  const cookieNamed = (name: string, raw: string, maxAge: number | undefined) =>
    `${secure ? '__Host-' : ''}${name}=${encodeURIComponent(raw)}; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=${sameSite === 'strict' ? 'Strict' : 'Lax'}; Path=/${maxAge === undefined ? '' : `; Max-Age=${maxAge}`}`;
  const cookie = (raw: string, maxAge: number | undefined) =>
    cookieNamed('better-iam.session', raw, maxAge);
  // Seconds left until `expiresAt` on the clock that stamped it (`authentication.now`), so an injected test clock
  // and the cookie agree instead of the cookie expiring at once or outliving its session.
  const secondsUntil = (expiresAt: number) =>
    Math.max(0, Math.floor((expiresAt - ctx.now()) / 1000));
  const sessionCookie = (
    result: { token: string; session: { expiresAt: number } },
    persistent: boolean,
  ) => cookie(result.token, persistent ? secondsUntil(result.session.expiresAt) : undefined);
  /** `X-Better-IAM-Persistent: 1|0` on the request that issues a session decides; otherwise the deployment default. */
  const persistentFor = (request: Request): boolean => {
    const header = request.headers.get('x-better-iam-persistent');
    if (header === '1') return true;
    if (header === '0') return false;
    return options.http?.persistentCookies ?? true;
  };
  // "Remember this device": the token lives in its own long-lived cookie and is injected into sign-in bodies.
  const deviceCookieName = `${secure ? '__Host-' : ''}better-iam.device`;
  const deviceCookie = (raw: string, expiresAt: number) =>
    cookieNamed('better-iam.device', raw, secondsUntil(expiresAt));
  const deviceCookieValue = (request: Request): string | undefined =>
    request.headers
      .get('cookie')
      ?.split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${deviceCookieName}=`))
      ?.slice(deviceCookieName.length + 1);
  const deviceTokenRoutes = new Set(['auth/signIn', 'auth/finishPasswordless']);

  async function protocolResponse(request: Request): Promise<Response | undefined> {
    for (const protocol of mountedProtocols) {
      const response = await protocol.handle?.(request);
      if (!response) continue;
      if (response.ok && response.headers.get('content-type')?.includes('application/json')) {
        try {
          const result = (await response.clone().json()) as {
            token?: unknown;
            session?: { expiresAt?: unknown };
          };
          if (typeof result.token === 'string' && typeof result.session?.expiresAt === 'number') {
            const headers = new Headers(response.headers);
            headers.append(
              'set-cookie',
              sessionCookie(
                { token: result.token, session: { expiresAt: result.session.expiresAt } },
                persistentFor(request),
              ),
            );
            return new Response(response.body, { status: response.status, headers });
          }
        } catch {
          /* A non-authentication protocol response does not issue an IAM cookie. */
        }
      }
      return response;
    }
    return undefined;
  }

  async function dispatch(
    path: string,
    body: Record<string, unknown>,
    credential: CredentialInput,
  ): Promise<unknown> {
    const { operations } = ctx;
    if (path === 'authorize') {
      const resource = object(body.resource);
      return operations.authorize({
        ...credential,
        tenantId: text(body.tenantId, 'tenantId'),
        action: text(body.action, 'action'),
        resource: {
          type: text(resource.type, 'resource type'),
          id: text(resource.id, 'resource id'),
        },
      });
    }
    if (path === 'authorizeMany')
      return operations.authorizeMany({
        ...credential,
        tenantId: text(body.tenantId, 'tenantId'),
        checks: body.checks as AuthorizationCheck[],
      });
    if (path === 'listAccessible')
      return operations.listAccessible({
        ...credential,
        tenantId: text(body.tenantId, 'tenantId'),
        action: text(body.action, 'action'),
        type: text(body.type, 'resource type', 64),
        limit: body.limit as number | undefined,
        offset: body.offset as number | undefined,
      });
    if (path.startsWith('plugins/')) {
      const [, pluginId, ...rest] = path.split('/');
      return operations.callPlugin(credential, {
        pluginId: text(pluginId, 'pluginId'),
        path: rest.join('/'),
        tenantId: text(body.tenantId, 'tenantId'),
        input: body,
      });
    }
    const [group, method, ...extra] = path.split('/');
    if (!group || !method || extra.length)
      throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
    if (group === 'auth') return dispatchAuth(method, body, credential);
    if (!routeGroups.has(group)) throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
    const target = (api as ApiSurface)[group];
    const fn = target && Object.hasOwn(target, method) ? target[method] : undefined;
    if (!fn) throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
    return publicApiMethods.has(`${group}/${method}`) ? fn(body) : fn(credential, body);
  }

  async function dispatchAuth(
    method: string,
    body: Record<string, unknown>,
    credential: CredentialInput,
  ): Promise<unknown> {
    const fn = Object.hasOwn(authApi, method)
      ? (authApi as Record<string, Callable>)[method]
      : undefined;
    if (!fn) throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
    // MFA enrollment takes either a sign-in challenge from the body or the request's own credential. Both go
    // through the wrapped `authApi` functions so they produce `auth` spans like every other method.
    if (method === 'beginMfa')
      return fn.call(
        auth,
        typeof body.challenge === 'string'
          ? { tenantId: text(body.tenantId, 'tenantId'), challenge: body.challenge }
          : credential,
      );
    if (method === 'confirmMfa') {
      const challenge = body.credential ? object(body.credential) : {};
      return fn.call(auth, {
        credential:
          typeof challenge.challenge === 'string'
            ? { tenantId: text(challenge.tenantId, 'tenantId'), challenge: challenge.challenge }
            : credential,
        code: text(body.code, 'code'),
        rememberDevice: body.rememberDevice === true,
      });
    }
    if (publicAuthMethods.has(method)) return fn.call(auth, body);
    if (authenticatedAuthMethods.has(method)) return fn.call(auth, credential, body);
    throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
  }

  /**
   * The `http` span name for a request path: the route when the route table (or a registered plugin endpoint)
   * knows it, otherwise `(unknown)`. The path is caller-controlled, so naming spans by it verbatim would let
   * anonymous requests mint unbounded metric series and span names.
   */
  function routeName(path: string): string {
    if (path === 'authorize' || path === 'authorizeMany' || path === 'listAccessible') return path;
    const [group, method, ...extra] = path.split('/');
    if (group === 'plugins') {
      const endpointPath = extra.join('/').replace(/^\//, '');
      const endpoint = ctx.plugins
        .find((plugin) => plugin.id === method)
        ?.endpoints?.find(
          (candidate) =>
            candidate.method === 'POST' && candidate.path.replace(/^\//, '') === endpointPath,
        );
      return endpoint ? `plugins/${method}/${endpointPath}` : '(unknown)';
    }
    if (!group || !method || extra.length) return '(unknown)';
    if (group === 'auth')
      return Object.hasOwn(authApi, method) &&
        (publicAuthMethods.has(method) || authenticatedAuthMethods.has(method))
        ? path
        : '(unknown)';
    const target = routeGroups.has(group) ? (api as ApiSurface)[group] : undefined;
    return target && Object.hasOwn(target, method) ? path : '(unknown)';
  }

  /**
   * Unauthenticated GET endpoints for operators: `/health` checks the database with one read and never reveals
   * more than up/down; `/metrics` serves the Prometheus text format to the configured bearer token only;
   * `/.well-known/jwks.json` publishes the session JWT verification keys (404 without `sts.jwt`).
   */
  async function operational(pathname: string, request: Request): Promise<Response> {
    const noStore = hardened;
    if (pathname === `${basePath}/health`) {
      const started = Date.now();
      try {
        // A lookup by primary key costs the same however many tenants exist: an anonymous probe must not scan
        // and parse a whole collection. A missing row still proves the database answers.
        await store.get('tenants', 'health-probe');
        return Response.json(
          { status: 'ok', database: 'ok', latencyMs: Date.now() - started, time: started },
          { headers: noStore },
        );
      } catch {
        return Response.json(
          { status: 'unavailable', database: 'error', time: started },
          { status: 503, headers: noStore },
        );
      }
    }
    // The public keys downstream services verify session JWTs with (`sts.jwt`): public members only, cacheable for
    // five minutes, so a key rotation waits at least that long before a new key signs (see the deployment guide).
    if (pathname === `${basePath}/.well-known/jwks.json`) {
      if (!ctx.sessionTokens) throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
      return Response.json(ctx.sessionTokens.publicJwks(), {
        headers: {
          ...noStore,
          'cache-control': 'public, max-age=300',
          'content-type': 'application/jwk-set+json',
        },
      });
    }
    if (pathname === `${basePath}/metrics` && extras.metrics && extras.metricsToken) {
      const provided = request.headers.get('authorization') ?? '';
      const expected = `Bearer ${extras.metricsToken}`;
      // Fixed-length digests: comparing raw strings would throw on a non-ASCII header whose character count
      // matches but whose byte length does not, and the length check would reveal the token's length.
      const digest = (value: string) => createHash('sha256').update(value).digest();
      if (!timingSafeEqual(digest(provided), digest(expected)))
        throw new IamError('UNAUTHENTICATED', 'A metrics bearer token is required', 401);
      const body = extras.metricsGauges
        ? `${extras.metrics.render()}${await storageGauges()}`
        : extras.metrics.render();
      return new Response(body, {
        headers: { ...noStore, 'content-type': 'text/plain; version=0.0.4; charset=utf-8' },
      });
    }
    throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
  }

  /** Point-in-time gauges read from storage on each scrape: outbox backlog and unexpired sessions. */
  async function storageGauges(): Promise<string> {
    // The authentication clock, which stamped `expiresAt`, decides which sessions are still live.
    const now = ctx.now();
    const [outbox, sessions] = await Promise.all([
      store.find<OutboxMessage>('outbox'),
      store.find<Session>('sessions'),
    ]);
    const pending = outbox.filter((message) => !message.deliveredAt && !message.failedAt).length;
    const failed = outbox.filter((message) => message.failedAt).length;
    const live = sessions.filter((session) => session.expiresAt > now);
    const count = (kind: Session['kind']) => live.filter((session) => session.kind === kind).length;
    return [
      '# HELP better_iam_outbox_messages Delivery outbox messages by state.',
      '# TYPE better_iam_outbox_messages gauge',
      `better_iam_outbox_messages{state="pending"} ${pending}`,
      `better_iam_outbox_messages{state="failed"} ${failed}`,
      '# HELP better_iam_sessions_live Unexpired sessions by kind.',
      '# TYPE better_iam_sessions_live gauge',
      `better_iam_sessions_live{kind="user"} ${count('user')}`,
      `better_iam_sessions_live{kind="api-key"} ${count('api-key')}`,
      `better_iam_sessions_live{kind="role"} ${count('role')}`,
      `better_iam_sessions_live{kind="session-token"} ${count('session-token')}`,
      `better_iam_sessions_live{kind="delegated"} ${count('delegated')}`,
      '',
    ].join('\n');
  }

  async function handler(request: Request): Promise<Response> {
    const requestId = requestIdOf(request);
    // Headers every IAM answer carries, errors and GET endpoints included: the request ID, and the CORS headers once
    // the Origin is known to be trusted, so a cross-origin browser client can read error codes, `Retry-After`, and
    // the request ID instead of seeing a network error. An untrusted Origin's refusal carries no CORS headers.
    const answerHeaders: Record<string, string> = requestId ? { 'x-request-id': requestId } : {};
    const answer = (response: Response) => withHeaders(response, answerHeaders);
    try {
      // Protocol mounts (the SAML ACS, OAuth login callbacks) issue sessions too: they run with the request's
      // client so network allowlists, blocks, and IP binding judge those sessions like any other sign-in.
      const client = clientFromRequest(options, request);
      const mounted = await auth.withClient(client, () => protocolResponse(request));
      if (mounted) return withRequestId(mounted, requestId);
      const url = new URL(request.url);
      if (!url.pathname.startsWith(`${basePath}/`))
        return answer(
          Response.json({ error: { code: 'NOT_FOUND', message: 'Not found' } }, { status: 404 }),
        );
      const origin = request.headers.get('origin');
      if (origin) {
        // Organization addresses (`hosts`) are trusted like the deployment's own origins: the deployment serves them.
        if (!trustedOrigins.has(origin) && !(await ctx.hosts.trustsOrigin(origin)))
          throw new IamError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
        answerHeaders['access-control-allow-origin'] = origin;
        answerHeaders['access-control-allow-credentials'] = 'true';
        answerHeaders['access-control-expose-headers'] = 'retry-after, x-request-id';
        answerHeaders.vary = 'Origin';
      }
      if (request.method === 'OPTIONS')
        return answer(
          new Response(null, {
            status: 204,
            headers: {
              'access-control-allow-methods': 'GET, POST, OPTIONS',
              'access-control-allow-headers':
                'content-type, x-better-iam, authorization, x-request-id, x-better-iam-persistent',
            },
          }),
        );
      // Awaited so a refusal inside becomes an error response like every other failure here.
      if (request.method === 'GET') return answer(await operational(url.pathname, request));
      if (request.method !== 'POST') throw new IamError('METHOD_NOT_ALLOWED', 'Use POST', 405);
      if (
        !request.headers.get('content-type')?.toLowerCase().startsWith('application/json') ||
        request.headers.get('x-better-iam') !== '1'
      )
        throw new IamError('CSRF_REJECTED', 'JSON and X-Better-IAM header required', 403);
      if (request.headers.has('cookie') && !origin)
        throw new IamError('CSRF_REJECTED', 'Cookie requests require Origin', 403);
      const raw = await limitedBody(request, 65536);
      let body: Record<string, unknown>;
      try {
        body = object(JSON.parse(raw));
      } catch {
        throw new IamError('INVALID_INPUT', 'Invalid JSON');
      }
      const path = url.pathname.slice(basePath.length + 1);
      const [group, method] = path.split('/');
      const publicRoute =
        group === 'auth' ? publicAuthMethods.has(method ?? '') : publicApiMethods.has(path);
      // On an organization's own address the request is pinned to that organization: public sign-in calls act in
      // it (the tenantId may be left out) and never in another, and credentials of other organizations are refused.
      // An organization another region serves is answered with WRONG_REGION and its sign-in URL there.
      const pinned = await ctx.hosts.requestTenant(request);
      if (publicRoute && (group === 'auth' || tenantBoundPublicMethods.has(path))) {
        if (pinned) {
          if (body.tenantId === undefined) body.tenantId = pinned.tenantId;
          else if (body.tenantId !== pinned.tenantId)
            throw new IamError(
              'HOST_MISMATCH',
              'This address belongs to another organization',
              403,
            );
        } else if (typeof body.tenantId === 'string')
          await ctx.hosts.assertTenantServedHere(body.tenantId);
      }
      const tenantId = typeof body.tenantId === 'string' ? body.tenantId : undefined;
      // A bearer credential takes precedence over the cookie (as in `auth.authenticate`), so a bearer-authenticated
      // request neither replaces nor clears the browser's session cookie: that session is not the one in play.
      // Public routes (sign-in ceremonies, invitations) use no request credential, so the header is moot there.
      const bearer = !publicRoute && Boolean(request.headers.get('authorization'));
      // The IamError code of a refused request, reported on the span (the error became a response inside it).
      let code: string | undefined;
      return await ctx.observe.span(
        'http',
        routeName(path),
        tenantId,
        async () => {
          try {
            if (deviceTokenRoutes.has(path) && body.deviceToken === undefined) {
              const remembered = deviceCookieValue(request);
              if (remembered) body.deviceToken = decodeURIComponent(remembered);
            }
            const result = await auth.withClient(client, () =>
              auth.withRequestHost(
                { origin: origin ?? undefined, tenantId: pinned?.tenantId },
                () => dispatch(path, body, { headers: request.headers }),
              ),
            );
            const headers = new Headers(hardened);
            if (
              !bearer &&
              sessionCookieRoutes.has(path) &&
              result &&
              typeof result === 'object' &&
              'token' in result &&
              'session' in result
            )
              headers.append(
                'set-cookie',
                sessionCookie(
                  result as { token: string; session: { expiresAt: number } },
                  persistentFor(request),
                ),
              );
            if (
              result &&
              typeof result === 'object' &&
              'deviceToken' in result &&
              typeof result.deviceToken === 'string' &&
              'deviceExpiresAt' in result &&
              typeof result.deviceExpiresAt === 'number'
            )
              headers.append(
                'set-cookie',
                deviceCookie(result.deviceToken, result.deviceExpiresAt),
              );
            if (path === 'auth/signOut' && !bearer) headers.set('set-cookie', cookie('', 0));
            if (path === 'auth/revokeTrustedDevices')
              headers.append('set-cookie', deviceCookie('', 0));
            return answer(Response.json({ data: publicResult(result) }, { headers }));
          } catch (error) {
            code = error instanceof IamError ? error.code : 'INTERNAL_ERROR';
            const response = errorResponse(error);
            // Signing out forgets the browser's cookie even when the sign-out is refused (the session idled out,
            // was revoked, or is presented from another network): clearing a cookie can never grant anything.
            if (path === 'auth/signOut' && !bearer)
              response.headers.append('set-cookie', cookie('', 0));
            return answer(response);
          }
        },
        (response) => ({
          status: response.status,
          outcome: response.ok ? 'ok' : deniedStatuses.has(response.status) ? 'denied' : 'error',
          ...(code ? { code } : {}),
        }),
        requestId ? { requestId } : undefined,
      );
    } catch (error) {
      return answer(errorResponse(error));
    }
  }

  async function nodeHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (['TRACE', 'CONNECT', 'TRACK'].includes(req.method ?? ''))
        throw new IamError('METHOD_NOT_ALLOWED', 'Method is not supported', 405);
      let url: URL;
      try {
        // With organization addresses the request keeps the host it was sent to, which decides its organization;
        // otherwise every request is resolved against the deployment's own address, as before.
        const host = ctx.hosts.enabled ? normalizeHost(req.headers.host) : undefined;
        url = new URL(req.url ?? '/', host ? `${baseURL.protocol}//${host}` : baseURL);
      } catch {
        throw new IamError('INVALID_REQUEST', 'Invalid request target', 400);
      }
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers))
        if (value)
          for (const item of Array.isArray(value) ? value : [value]) headers.append(key, item);
      // Node protocol mounts (the OAuth provider, federation callbacks) run with the request's client, like the
      // fetch transport, so any session they issue is judged by network allowlists, blocks, and IP binding.
      const client = mountedProtocols.some((protocol) => protocol.nodeHandler)
        ? clientFromRequest(options, new Request(url, { headers }))
        : undefined;
      const handled = await auth.withClient(client, async () => {
        for (const protocol of mountedProtocols) {
          if (!protocol.nodeHandler) continue;
          if ((await protocol.nodeHandler(req, res)) || res.writableEnded) return true;
        }
        return false;
      });
      if (handled) return;
      const chunks: Buffer[] = [];
      let size = 0;
      const maxBody = url.pathname.startsWith(`${basePath}/`) ? 65536 : 2097152;
      for await (const chunk of req) {
        const buffer = Buffer.from(chunk);
        size += buffer.length;
        if (size > maxBody) {
          res.statusCode = 413;
          res.end('Request too large');
          return;
        }
        chunks.push(buffer);
      }
      const response = await handler(
        new Request(url, {
          method: req.method,
          headers,
          body: req.method === 'GET' || req.method === 'HEAD' ? undefined : Buffer.concat(chunks),
        }),
      );
      res.statusCode = response.status;
      response.headers.forEach((value, key) => {
        if (key !== 'set-cookie') res.setHeader(key, value);
      });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader('set-cookie', cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      if (res.writableEnded || res.destroyed) return;
      if (res.headersSent) {
        res.destroy();
        return;
      }
      const known = error instanceof IamError;
      res.statusCode = known ? error.status : 500;
      res.setHeader('content-type', 'application/json');
      res.setHeader('cache-control', 'no-store');
      res.end(
        JSON.stringify({
          error: {
            code: known ? error.code : 'INTERNAL_ERROR',
            message: known ? error.message : 'Internal server error',
          },
        }),
      );
    }
  }

  /** Mounts a protocol service under its base path for both transports. */
  function useProtocol(protocol: ProtocolService): void {
    const path = protocol.basePath.replace(/\/$/, '');
    mountedProtocols.push({
      handle: protocol.handler ? (request) => protocol.handler!(request) : undefined,
      nodeHandler: protocol.nodeHandler
        ? async (req, res) => {
            const pathname = new URL(req.url ?? '/', baseURL).pathname;
            if (
              pathname !== path &&
              !pathname.startsWith(`${path}/`) &&
              pathname !== `/.well-known/oauth-authorization-server${path}`
            )
              return false;
            await protocol.nodeHandler!(req, res);
            return true;
          }
        : undefined,
    });
  }

  return { handler, nodeHandler, useProtocol };
}

export type AuthApi = ReturnType<typeof createAuthApi>;
/**
 * End-user authentication operations, bound to the auth service; the router decides which are public. With
 * `clientOf`, a call made outside the HTTP handler whose credential carries the incoming request's headers (framework
 * integrations pass `{ headers }`) runs with the client derived from them.
 */
export function createAuthApi(
  auth: AuthService,
  observe?: Observer,
  clientOf?: (headers: HeadersInit) => SessionClientInfo | undefined,
) {
  const api = {
    signUp: auth.signUp.bind(auth),
    signIn: auth.signIn.bind(auth),
    signOut: auth.signOut.bind(auth),
    getSession: auth.getSession.bind(auth),
    listSessions: auth.listSessions.bind(auth),
    revokeSession: auth.revokeSession.bind(auth),
    revokeOtherSessions: auth.revokeOtherSessions.bind(auth),
    requestEmailVerification: auth.requestEmailVerification.bind(auth),
    verifyEmail: auth.verifyEmail.bind(auth),
    requestPasswordReset: auth.requestPasswordReset.bind(auth),
    resetPassword: auth.resetPassword.bind(auth),
    changePassword: auth.changePassword.bind(auth),
    reauthenticate: auth.reauthenticate.bind(auth),
    requestEmailChange: auth.requestEmailChange.bind(auth),
    confirmEmailChange: auth.confirmEmailChange.bind(auth),
    startPhoneVerification: auth.startPhoneVerification.bind(auth),
    confirmPhoneVerification: auth.confirmPhoneVerification.bind(auth),
    startPasswordless: auth.startPasswordless.bind(auth),
    finishPasswordless: auth.finishPasswordless.bind(auth),
    beginMfa: auth.beginMfa.bind(auth),
    confirmMfa: auth.confirmMfa.bind(auth),
    verifyMfa: auth.verifyMfa.bind(auth),
    requestMfaCode: auth.requestMfaCode.bind(auth),
    recoverMfa: auth.recoverMfa.bind(auth),
    beginPasskeyRegistration: auth.beginPasskeyRegistration.bind(auth),
    finishPasskeyRegistration: auth.finishPasskeyRegistration.bind(auth),
    beginPasskeyAuthentication: auth.beginPasskeyAuthentication.bind(auth),
    finishPasskeyAuthentication: auth.finishPasskeyAuthentication.bind(auth),
    beginPasskeyMfa: auth.beginPasskeyMfa.bind(auth),
    finishPasskeyMfa: auth.finishPasskeyMfa.bind(auth),
    listPasskeys: auth.listPasskeys.bind(auth),
    deletePasskey: auth.deletePasskey.bind(auth),
    renamePasskey: auth.renamePasskey.bind(auth),
    regenerateRecoveryCodes: auth.regenerateRecoveryCodes.bind(auth),
    disableMfa: auth.disableMfa.bind(auth),
    listTrustedDevices: auth.listTrustedDevices.bind(auth),
    revokeTrustedDevice: auth.revokeTrustedDevice.bind(auth),
    revokeTrustedDevices: auth.revokeTrustedDevices.bind(auth),
    listSecurityEvents: auth.listSecurityEvents.bind(auth),
    mfaStatus: auth.mfaStatus.bind(auth),
  };
  if (!observe?.enabled && !clientOf) return api;
  /**
   * The request headers a call carries: the credential itself (`{ headers }`), or the credential of an MFA
   * enrollment (`{ credential: { headers } }`).
   */
  const headersOf = (first: unknown): HeadersInit | undefined => {
    if (!first || typeof first !== 'object') return undefined;
    const direct = (first as CredentialInput).headers;
    if (direct) return direct;
    const nested = (first as { credential?: unknown }).credential;
    return nested && typeof nested === 'object' ? (nested as CredentialInput).headers : undefined;
  };
  // Each call is timed as an `auth` span named after the method; the tenant is taken from the input when present.
  for (const name of Object.keys(api) as (keyof typeof api)[]) {
    const fn = api[name] as (...args: unknown[]) => Promise<unknown>;
    (api as Record<string, unknown>)[name] = (...args: unknown[]) => {
      const first = args[0];
      const call = () => fn(...args);
      // Outside the HTTP handler no client is in scope, so IP binding, network allowlists, and blocks could not
      // judge the presented session and a stolen cookie replayed through an app route would work from anywhere.
      // The client comes from the same headers (and `http.clientInfo`) the handler would use; a scope the caller
      // set with `withClient`, or the handler's own, is never replaced.
      const headers = clientOf && !auth.currentClient() ? headersOf(first) : undefined;
      const scoped = headers ? () => auth.withClient(clientOf!(headers), call) : call;
      if (!observe?.enabled) return scoped();
      const tenantId =
        first &&
        typeof first === 'object' &&
        typeof (first as { tenantId?: unknown }).tenantId === 'string'
          ? (first as { tenantId: string }).tenantId
          : undefined;
      return observe.span('auth', name, tenantId, scoped);
    };
  }
  return api;
}
