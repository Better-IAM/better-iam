/**
 * Edge-safe helpers: nothing here imports Node built-ins, React, or Next internals, so this module works in
 * middleware, edge route handlers, and any Web-standard runtime. Cryptography uses Web Crypto.
 */

/** The request header middleware forwards so server components know the path being rendered. */
export const pathnameHeader = 'x-better-iam-pathname';

/** The cookie name the server issues: host-prefixed on HTTPS, plain on loopback development. */
export function sessionCookieName(secure: boolean): string {
  return secure ? '__Host-better-iam.session' : 'better-iam.session';
}

/**
 * A same-origin path safe to redirect to after sign-in, or `fallback`. Rejects absolute URLs, protocol-relative
 * `//host`, backslash tricks, and control characters, so a `?next=` parameter cannot become an open redirect.
 */
export function safeRedirectPath(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return fallback;
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return fallback;
  }
  try {
    const resolved = new URL(value, 'http://better-iam.invalid');
    if (resolved.origin !== 'http://better-iam.invalid') return fallback;
    const path = `${resolved.pathname}${resolved.search}${resolved.hash}`;
    // Dot segments can normalize into a protocol-relative path: '/.//evil.example' resolves to '//evil.example'.
    return /^\/(?![/\\])/.test(path) ? path : fallback;
  } catch {
    return fallback;
  }
}

/** Glob over URL paths: `*` matches within one segment, `**` across segments. */
export function matchPath(pattern: string, pathname: string): boolean {
  let source = '';
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index]!;
    if (char === '*') {
      if (pattern[index + 1] === '*') {
        source += '.*';
        index++;
      } else source += '[^/]*';
    } else source += /[.+?^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
  }
  return new RegExp(`^${source}$`).test(pathname);
}

export interface IamMiddlewareOptions {
  /** Where visitors without a session cookie are sent. */
  loginPath: string;
  /** Which paths need a session. Defaults to everything except the login path, `/api/iam`, and `publicPaths`. */
  protect?: (pathname: string) => boolean;
  /** Extra public path globs (`/docs/**`, `/invite/*`) for the default `protect`. */
  publicPaths?: string[];
  /** Override cookie security detection (HTTPS uses the host-prefixed cookie). */
  secure?: boolean;
  /** Query parameter carrying the original path (default `next`); set to false to omit it. */
  nextParam?: string | false;
  /**
   * Visitors who already carry a session cookie and open the login path without `?next=` are sent here. A login
   * visit with `?next=` always renders: server guards add it when they find the cookie stale. Off by default.
   */
  signedInRedirect?: string;
  /**
   * `NextResponse.next` (pass `(init) => NextResponse.next(init)`). When given, requests that continue carry the
   * `x-better-iam-pathname` header so `requireSession` can fill `?next=` automatically.
   */
  next?: (init: { request: { headers: Headers } }) => Response;
}
export interface MiddlewareRequest {
  nextUrl: URL;
  cookies: { has(name: string): boolean };
  headers?: Headers;
}

/**
 * Edge-safe presence check for the session cookie: signed-out visitors are redirected before a protected page renders.
 * It is a routing convenience, not authorization; pages still call `requireSession` or `require`.
 */
export function createIamMiddleware(
  options: IamMiddlewareOptions,
): (request: MiddlewareRequest) => Response | undefined {
  const isLogin = (pathname: string) =>
    pathname === options.loginPath || pathname.startsWith(`${options.loginPath}/`);
  const publicPaths = options.publicPaths ?? [];
  const protect =
    options.protect ??
    ((pathname: string) =>
      !isLogin(pathname) &&
      !pathname.startsWith('/api/iam') &&
      !publicPaths.some((pattern) => matchPath(pattern, pathname)));
  const nextParam = options.nextParam === undefined ? 'next' : options.nextParam;
  return (request) => {
    const url = request.nextUrl;
    const secure = options.secure ?? url.protocol === 'https:';
    const signedIn = request.cookies.has(sessionCookieName(secure));
    // A login visit with ?next= was sent by a server guard that found no valid session: the cookie is stale, so the
    // page must render. Redirecting it back would loop between the guard and the middleware.
    const sentByGuard =
      url.searchParams.has('next') || (nextParam ? url.searchParams.has(nextParam) : false);
    if (signedIn && options.signedInRedirect && isLogin(url.pathname) && !sentByGuard)
      return Response.redirect(new URL(options.signedInRedirect, url), 307);
    if (!protect(url.pathname) || signedIn) {
      if (!options.next) return undefined;
      const headers = new Headers(request.headers);
      headers.set(pathnameHeader, `${url.pathname}${url.search}`);
      return options.next({ request: { headers } });
    }
    const target = new URL(options.loginPath, url);
    if (nextParam) target.searchParams.set(nextParam, `${url.pathname}${url.search}`);
    return Response.redirect(target, 307);
  };
}

const encoder = new TextEncoder();

function base64urlBytes(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return undefined;
  }
}
function hexBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++)
    bytes[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}
function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
async function hmacSha256(key: Uint8Array, data: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(data)));
}

/** The claims of a Better IAM stateless assertion (mirrors the server's `AssertionClaims`). */
export interface AssertionClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  tid: string;
  kind: 'user' | 'api-key' | 'role' | 'session-token';
  mfa: boolean;
  method?: string;
  impersonatorId?: string;
  name: string;
  email?: string;
  roles: string[];
  groups: string[];
  ext?: Record<string, unknown>;
}

/** Raised by the edge verifiers; `code` and `status` match the server's `IamError` for the same failure. */
export class AssertionError extends Error {
  readonly code = 'INVALID_ASSERTION';
  readonly status = 401;
  constructor(message: string) {
    super(message);
    this.name = 'AssertionError';
  }
}

export interface VerifyAssertionOptions {
  /**
   * `iam.assertionKey()` of the issuing deployment (64 hex characters), or the list from
   * `iam.assertionKeys()` while its secret rotates.
   */
  key: string | readonly string[];
  audience: string;
  issuer?: string;
  now?: number;
  toleranceSeconds?: number;
}

const assertionHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

/**
 * Verifies an assertion issued by `assertions.issue` with Web Crypto, so middleware and edge handlers can trust it
 * without a database. Same rules as the server's `verifyAssertion`: HS256 only, audience, optional issuer, and time.
 */
export async function verifyAssertionToken(
  token: string,
  options: VerifyAssertionOptions,
): Promise<AssertionClaims> {
  if (typeof token !== 'string' || token.length > 16384)
    throw new AssertionError('Malformed assertion');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== assertionHeader)
    throw new AssertionError('Malformed assertion');
  const keys = typeof options.key === 'string' ? [options.key] : options.key;
  if (
    !Array.isArray(keys) ||
    !keys.length ||
    keys.some((key) => typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key))
  )
    throw new AssertionError('Invalid verification key');
  const provided = base64urlBytes(parts[2]!);
  if (!provided) throw new AssertionError('Malformed assertion');
  let verified = false;
  for (const key of keys) {
    const expected = await hmacSha256(hexBytes(key), `${parts[0]}.${parts[1]}`);
    if (constantTimeEqual(provided, expected)) verified = true;
  }
  if (!verified) throw new AssertionError('Invalid signature');
  let claims: AssertionClaims;
  try {
    const payload = base64urlBytes(parts[1]!);
    if (!payload) throw new Error('payload');
    claims = JSON.parse(new TextDecoder().decode(payload)) as AssertionClaims;
  } catch {
    throw new AssertionError('Malformed assertion');
  }
  if (
    !claims ||
    typeof claims !== 'object' ||
    typeof claims.sub !== 'string' ||
    typeof claims.tid !== 'string' ||
    typeof claims.exp !== 'number' ||
    typeof claims.iat !== 'number'
  )
    throw new AssertionError('Malformed assertion');
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  const tolerance = options.toleranceSeconds ?? 30;
  if (claims.aud !== options.audience) throw new AssertionError('Audience mismatch');
  if (options.issuer !== undefined && claims.iss !== options.issuer)
    throw new AssertionError('Issuer mismatch');
  if (claims.exp + tolerance <= now) throw new AssertionError('Assertion expired');
  if (claims.iat - tolerance > now) throw new AssertionError('Assertion not yet valid');
  return claims;
}

function jsonError(code: string, message: string, status: number): Response {
  return Response.json(
    { error: { code, message } },
    { status, headers: { 'cache-control': 'no-store' } },
  );
}
function bearer(request: Request): string | undefined {
  const header = request.headers.get('authorization');
  const match = header ? /^Bearer\s+([A-Za-z0-9._-]+)$/i.exec(header) : null;
  return match?.[1];
}

/**
 * Route handler guard for services that receive assertions from a Better IAM application: the bearer token is
 * verified offline and its claims passed to the handler. Failures answer 401 with the server's error envelope.
 *
 * ```ts
 * export const GET = withAssertion({ key: process.env.IAM_ASSERTION_KEY!, audience: 'reports' },
 *   async (request, { claims }) => Response.json({ tenant: claims.tid }));
 * ```
 */
export function withAssertion<Context = unknown>(
  options: VerifyAssertionOptions & {
    /** Extra checks after verification, such as requiring `claims.mfa`; return false to answer 403. */
    authorize?: (claims: AssertionClaims) => boolean | Promise<boolean>;
  },
  handler: (
    request: Request,
    input: { claims: AssertionClaims; context: Context },
  ) => Response | Promise<Response>,
): (request: Request, context: Context) => Promise<Response> {
  return async (request, context) => {
    const token = bearer(request);
    if (!token) return jsonError('UNAUTHENTICATED', 'A bearer assertion is required', 401);
    let claims: AssertionClaims;
    try {
      claims = await verifyAssertionToken(token, options);
    } catch (error) {
      if (error instanceof AssertionError) return jsonError(error.code, error.message, 401);
      throw error;
    }
    if (options.authorize && !(await options.authorize(claims)))
      return jsonError('ACCESS_DENIED', 'The assertion does not permit this request', 403);
    return handler(request, { claims, context });
  };
}

/** The JSON body of a Better IAM webhook delivery (mirrors the server's `WebhookEvent`). */
export interface IamWebhookEvent {
  id: string;
  type: string;
  tenantId: string;
  actorId?: string;
  originalActorId?: string;
  impersonatorId?: string;
  resourceId?: string;
  outcome: string;
  timestamp: number;
  rootOverride?: boolean;
  metadata?: Record<string, unknown>;
  /** The session the actor used (mirrors the server's `AuditSessionContext`; `kind` is kept open for new kinds). */
  sessionContext?: {
    sessionId: string;
    kind: string;
    roleId?: string;
    trustId?: string;
    sourceTenantId?: string;
    sessionName?: string;
    sourceIdentity?: string;
    webIdentityProviderId?: string;
    webIdentitySubject?: string;
    format?: 'jwt';
  };
  sequence?: number;
  hash?: string;
}
export interface WebhookDeliveryInfo {
  deliveryId: string | null;
  webhookId: string | null;
  event: string | null;
  timestamp: number;
}

/**
 * Checks an `X-Better-IAM-Signature` header (`v1=<hex HMAC-SHA256 of "{timestamp}.{body}">`) with Web Crypto.
 * Equivalent to the server's `verifyWebhookSignature`, for edge runtimes.
 */
export async function verifyWebhook(input: {
  secret: string;
  timestamp: string | number;
  body: string;
  signature: string;
  toleranceSeconds?: number;
  now?: number;
}): Promise<boolean> {
  const timestamp = Number(input.timestamp);
  if (!Number.isFinite(timestamp)) return false;
  const tolerance = input.toleranceSeconds ?? 300;
  if (Math.abs(Math.floor((input.now ?? Date.now()) / 1000) - timestamp) > tolerance) return false;
  const provided = input.signature
    .split(',')
    .map((part) => part.trim())
    .find((part) => part.startsWith('v1='))
    ?.slice(3);
  if (!provided || !/^[0-9a-f]{64}$/.test(provided)) return false;
  const expected = await hmacSha256(encoder.encode(input.secret), `${timestamp}.${input.body}`);
  return constantTimeEqual(expected, hexBytes(provided));
}

export interface WebhookHandlerOptions {
  /** The subscription secret; pass several during rotation and any of them is accepted. */
  secret: string | string[];
  onEvent(event: IamWebhookEvent, delivery: WebhookDeliveryInfo): unknown | Promise<unknown>;
  /** Maximum clock skew, in seconds (default 300). */
  toleranceSeconds?: number;
  /** Largest accepted body, in bytes (default 1 MiB). */
  maxBodyBytes?: number;
}

/**
 * A route handler that receives Better IAM webhooks: `export const POST = createWebhookHandler({ secret, onEvent })`.
 * Unsigned, stale, or oversized requests answer 401/413 without calling `onEvent`; a throwing `onEvent` answers 500
 * so the sender retries with backoff. Deliveries can repeat: deduplicate on `event.id` or `delivery.deliveryId`.
 */
export function createWebhookHandler(
  options: WebhookHandlerOptions,
): (request: Request) => Promise<Response> {
  const secrets = Array.isArray(options.secret) ? options.secret : [options.secret];
  if (!secrets.length || secrets.some((secret) => typeof secret !== 'string' || !secret))
    throw new TypeError('createWebhookHandler requires a webhook secret');
  const limit = options.maxBodyBytes ?? 1048576;
  return async (request) => {
    if (request.method !== 'POST') return jsonError('METHOD_NOT_ALLOWED', 'Use POST', 405);
    const declared = Number(request.headers.get('content-length') ?? 0);
    if (declared > limit) return jsonError('PAYLOAD_TOO_LARGE', 'Webhook body too large', 413);
    const body = await request.text();
    if (encoder.encode(body).length > limit)
      return jsonError('PAYLOAD_TOO_LARGE', 'Webhook body too large', 413);
    const timestamp = request.headers.get('x-better-iam-timestamp') ?? '';
    const signature = request.headers.get('x-better-iam-signature') ?? '';
    let valid = false;
    for (const secret of secrets)
      if (
        await verifyWebhook({
          secret,
          timestamp,
          body,
          signature,
          ...(options.toleranceSeconds === undefined
            ? {}
            : { toleranceSeconds: options.toleranceSeconds }),
        })
      ) {
        valid = true;
        break;
      }
    if (!valid) return jsonError('INVALID_SIGNATURE', 'Webhook signature is invalid', 401);
    let event: IamWebhookEvent;
    try {
      event = JSON.parse(body) as IamWebhookEvent;
    } catch {
      return jsonError('INVALID_INPUT', 'Webhook body is not JSON', 400);
    }
    if (!event || typeof event !== 'object' || typeof event.type !== 'string')
      return jsonError('INVALID_INPUT', 'Webhook body is not an event', 400);
    try {
      await options.onEvent(event, {
        deliveryId: request.headers.get('x-better-iam-delivery'),
        webhookId: request.headers.get('x-better-iam-webhook'),
        event: request.headers.get('x-better-iam-event'),
        timestamp: Number(timestamp),
      });
    } catch {
      return jsonError('HANDLER_FAILED', 'The webhook handler failed', 500);
    }
    return Response.json({ received: true }, { headers: { 'cache-control': 'no-store' } });
  };
}
