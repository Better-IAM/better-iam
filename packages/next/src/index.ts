import * as React from 'react';
import type { ReactNode } from 'react';
import type { IncomingHttpHeaders } from 'node:http';
import type { ParsedUrlQuery } from 'node:querystring';
import type {
  GetServerSidePropsContext,
  GetServerSidePropsResult,
  NextApiRequest,
  NextApiResponse,
} from 'next';
import { IamError, type AuthMethod, type CredentialInput } from '@better-iam/core';
import { createIamClient, type IamClient } from '@better-iam/client';
import { pathnameHeader, safeRedirectPath, sessionCookieName } from './edge.js';
import { createAuthActions, type AuthActions, type AuthActionsOptions } from './auth-actions.js';
import {
  createBackground,
  type BackgroundIam,
  type BackgroundOptions,
  type IamBackground,
} from './background.js';

export * from './edge.js';
export * from './auth-types.js';
export * from './auth-actions.js';
export * from './background.js';

/** The server surface these helpers use; a `betterIam()` instance satisfies it. */
export interface IamLike {
  api: {
    auth: { getSession(credential: CredentialInput): Promise<unknown> };
    assertions?: {
      issue(credential: CredentialInput, input: AssertionInput): Promise<unknown>;
    };
    tenants?: { lookup(input: { slug: string }): Promise<TenantSummary> };
  };
  /** Resolves any credential the server accepts (user sessions, API keys, assumed roles); used by `apiRoute`. */
  authenticate?(input: CredentialInput): Promise<{ identity: unknown; session: unknown }>;
  handler(request: Request): Promise<Response>;
  require(
    request: CredentialInput & {
      tenantId: string;
      action: string;
      resource: { type: string; id: string };
    },
  ): Promise<void>;
  authorizeMany(
    request: CredentialInput & { tenantId: string; checks: AuthorizeCheck[] },
  ): Promise<{ results: (AuthorizeCheck & { allowed: boolean; reason: string })[] }>;
  /** Where the HTTP handler is mounted; `betterIam()` provides it. */
  endpoint?: { origin: string; basePath: string; secure?: boolean };
  /** Organization sign-in addresses; when present, in-process calls keep the visitor's host so they are pinned. */
  hosts?: { resolve(host: string): Promise<unknown> };
}
export interface AuthorizeCheck {
  action: string;
  resource: { type: string; id: string };
}
export interface AssertionInput {
  tenantId: string;
  audience: string;
  ttlSeconds?: number;
  claims?: Record<string, unknown>;
}
export interface TenantSummary {
  tenantId: string;
  name: string;
  type: string;
  slug: string;
}
export type ResourceRef = { type: string; id: string };
export type SessionOf<T extends IamLike> = Awaited<ReturnType<T['api']['auth']['getSession']>>;
export type AssertionOf<T extends IamLike> = T['api'] extends {
  assertions: { issue(...args: never[]): infer Result };
}
  ? Awaited<Result>
  : unknown;
export type HeaderSource = Headers | HeadersInit | Promise<Headers>;

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
}
/** The part of Next's `cookies()` store the helpers use. */
export interface CookieStore {
  set(name: string, value: string, options?: CookieOptions): unknown;
  toString(): string;
}

/** The serializable outcome of a guarded server action, suitable for `useActionState`. */
export type ActionResult<Data> =
  | { ok: true; data: Data }
  | { ok: false; error: { code: string; message: string } };

export interface IamNextOptions {
  /** Where `requireSession` sends signed-out visitors (default `/login`). */
  loginPath?: string;
  /** Reads the current request headers; defaults to `headers()` merged with `cookies()` from `next/headers`. */
  headers?: () => Headers | Promise<Headers>;
  /** The mutable cookie store used by `client()`; defaults to `cookies()` from `next/headers`. */
  cookies?: () => CookieStore | Promise<CookieStore>;
  /** Performs a redirect; defaults to `redirect()` from `next/navigation`. */
  redirect?: (url: string) => never | Promise<never>;
  /**
   * Use Next's auth interrupts (`experimental.authInterrupts`): signed-out requests without an explicit `redirectTo`
   * call `unauthorized()` and denials call `forbidden()`, rendering `unauthorized.tsx` / `forbidden.tsx`. `'forbidden'`
   * interrupts denials only and keeps redirecting signed-out visitors to the login path.
   */
  interrupts?: boolean | 'forbidden';
  /** Overrides for `unauthorized()`, `forbidden()`, and `notFound()` from `next/navigation`. */
  unauthorized?: () => never | Promise<never>;
  forbidden?: () => never | Promise<never>;
  notFound?: () => never | Promise<never>;
  /**
   * Memoizes the ambient session read per request; defaults to React's `cache`, so a layout and its page share
   * one `getSession` round trip.
   */
  cache?: <F extends (...args: never[]) => unknown>(fn: F) => F;
  /** The IAM origin and base path for `client()` when the instance does not report `endpoint`. */
  baseURL?: string;
  basePath?: string;
  /**
   * The page that re-authenticates people for `stepUp` guards (for example `/reauth`); it receives `?next=` and
   * `?reason=` (`mfa`, `recent`, or `impersonation`). Without it, page guards throw the step-up error instead: an
   * `IamError` with the failure's `code`, `status`, and `reason`, whose `digest` is `BETTER_IAM_STEP_UP:<code>:<reason>`.
   * Production builds pass only the digest to `error.tsx`, so boundaries recognize step-up failures by that prefix.
   */
  stepUpPath?: string;
  /** The clock for step-up recency checks; defaults to `Date.now`. */
  now?: () => number;
  /**
   * Origins besides this application's own whose pages may send cookie-authenticated mutations to handlers wrapped
   * by `route`, `apiRoute`, and `pages.api` (for example a separate front end). The IAM instance's origin is trusted.
   */
  trustedOrigins?: string[];
  /**
   * Deliver queued email, SMS, and webhooks and dispatch events after responses, with Next's `after()`: every call
   * through `client()`, `pages.client()`, and the `handlers()` / `pages.handler()` mounts schedules a run, so no
   * separate worker is needed for interactive traffic. Pair it with `background.cron()` for retries and quiet hours.
   */
  dispatchAfterResponse?: boolean;
  /** Options for `background` (error reporting, batch size, an `after()` override). */
  background?: BackgroundOptions;
}

/**
 * Extra assurance a guard demands beyond a valid session. The server has no in-place step-up: the step-up page
 * signs the person in again (`auth.reauthenticate`, then MFA when enrolled), which issues a new session.
 */
export interface StepUpRequirement {
  /**
   * `true` requires a session that completed MFA; impersonated sessions and assumed roles inherit it from the session
   * they came from. `'fresh'` requires a user session that verified the factor itself: it refuses sessions a
   * remembered device satisfied, impersonated sessions, assumed roles, and API keys. Sessions from `links.switch`
   * do not carry the remembered-device marker, so `'fresh'` cannot tell them apart.
   */
  mfa?: boolean | 'fresh';
  /**
   * The session must have authenticated within this many milliseconds; impersonated sessions never qualify, and
   * neither do temporary credentials (assumed roles, session tokens, or anything with a source session).
   */
  maxAgeMs?: number;
  /** Where page guards send people to step up; defaults to the `stepUpPath` option. */
  redirectTo?: string;
}
/** Why a session falls short of a `StepUpRequirement`, with the code and status the server uses for the same case. */
export interface StepUpFailure {
  code: 'MFA_REQUIRED' | 'RECENT_AUTH_REQUIRED' | 'IMPERSONATION_RESTRICTED';
  reason: 'mfa' | 'recent' | 'impersonation';
  message: string;
  status: 403;
}
function validateStepUp(requirement: StepUpRequirement): void {
  const { mfa, maxAgeMs } = requirement;
  if (mfa !== undefined && typeof mfa !== 'boolean' && mfa !== 'fresh')
    throw new TypeError("stepUp.mfa must be true, false, or 'fresh'");
  if (
    maxAgeMs !== undefined &&
    (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0)
  )
    throw new TypeError('stepUp.maxAgeMs must be a positive, finite number of milliseconds');
}
/**
 * Checks a session against a step-up requirement; null when it qualifies. Accepts the `getSession` result, its inner
 * session record, or an `apiRoute` principal. Impersonated sessions always fail a recency requirement, as the
 * server's own check does, and `mfa: 'fresh'` fails closed whenever the record cannot show a first-hand factor.
 */
export function checkStepUp(
  session: unknown,
  requirement: StepUpRequirement,
  now: number = Date.now(),
): StepUpFailure | null {
  validateStepUp(requirement);
  const outer = session && typeof session === 'object' ? (session as { session?: unknown }) : {};
  const record = (
    outer.session && typeof outer.session === 'object' ? outer.session : outer
  ) as Record<string, unknown>;
  const fail = (
    code: StepUpFailure['code'],
    reason: StepUpFailure['reason'],
    message: string,
  ): StepUpFailure => ({ code, reason, message, status: 403 });
  const impersonated = Boolean(record.impersonatorId) || record.method === 'impersonation';
  if (impersonated && (requirement.maxAgeMs !== undefined || requirement.mfa === 'fresh'))
    return fail(
      'IMPERSONATION_RESTRICTED',
      'impersonation',
      'This operation is unavailable while impersonating a member',
    );
  if (requirement.mfa && record.mfa !== true)
    return fail('MFA_REQUIRED', 'mfa', 'Multi-factor authentication is required');
  if (requirement.mfa === 'fresh') {
    if (record.trustedDeviceId)
      return fail('MFA_REQUIRED', 'mfa', 'Verify your second factor again to continue');
    // Assumed roles (and anything else derived from another session) copy its MFA flag but not how it was met.
    // That covers session tokens (kind 'session-token') and signed session JWTs too: none of them is kind 'user'.
    if (record.kind !== 'user' || record.sourceSessionId)
      return fail(
        'MFA_REQUIRED',
        'mfa',
        'This credential cannot show a fresh second factor; use a signed-in session',
      );
  }
  if (requirement.maxAgeMs !== undefined) {
    // As the server's requireRecent: temporary credentials (assumed roles, session tokens, anything derived from
    // another session, or a kind this version does not know) inherit their source's sign-in time, so they never
    // count as a recent sign-in. A record without a kind (hand-built) is judged by its time alone.
    const kind = record.kind;
    if (
      (kind !== undefined && kind !== 'user' && kind !== 'api-key') ||
      Boolean(record.sourceSessionId)
    )
      return fail(
        'RECENT_AUTH_REQUIRED',
        'recent',
        'Temporary credentials cannot perform this operation; use a signed-in session',
      );
    const at = record.authenticatedAt;
    if (typeof at !== 'number' || at > now || !(now - at <= requirement.maxAgeMs))
      return fail('RECENT_AUTH_REQUIRED', 'recent', 'Reauthenticate to perform this operation');
  }
  return null;
}
/** The thrown form of a failure; Next keeps a preset `digest` through production redaction, unlike other fields. */
function stepUpError(failure: StepUpFailure): IamError & StepUpFailure & { digest: string } {
  return Object.assign(new IamError(failure.code, failure.message, failure.status), failure, {
    digest: `BETTER_IAM_STEP_UP:${failure.code}:${failure.reason}`,
  });
}

/**
 * The caller of an `apiRoute`: a user session, an API key (of a service account or an AI agent), an assumed-role
 * session, a session token (from `sts.getSessionToken`), or a delegated session in which an AI agent acts for the
 * identity. Opaque tokens and IAM-signed session JWTs resolve to the same shape. Only these public fields are copied
 * from the stored records, so token hashes, session policies and tags never reach application code.
 */
export interface IamPrincipal {
  identity: {
    id: string;
    tenantId: string;
    name: string;
    email?: string;
    kind?: 'user' | 'service' | 'agent';
    status?: string;
  };
  session: {
    id: string;
    /** The tenant the credential acts in; for an assumed role this differs from the identity's tenant. */
    tenantId: string;
    kind: 'user' | 'role' | 'api-key' | 'session-token' | 'delegated';
    /** Delegated sessions: the AI agent acting for the identity, and the delegation it acts under. */
    agentId?: string;
    delegationId?: string;
    mfa: boolean;
    method?: AuthMethod;
    authenticatedAt: number;
    expiresAt: number;
    roleId?: string;
    impersonatorId?: string;
    /** Set when a remembered device met the MFA requirement instead of a fresh second factor. */
    trustedDeviceId?: string;
    /** The caller-chosen name of a role session or session token, when one was supplied. */
    sessionName?: string;
    /** The source identity a role session carries (caller-supplied or from a web-identity claim), when set. */
    sourceIdentity?: string;
  };
}
function toPrincipal(raw: { identity: unknown; session: unknown }): IamPrincipal {
  const identity = (raw.identity ?? {}) as Record<string, unknown>;
  const session = (raw.session ?? {}) as Record<string, unknown>;
  const { id, tenantId, name, email, kind: identityKind, status } = identity;
  const { id: sessionId, tenantId: sessionTenant, kind, method, roleId } = session;
  const { impersonatorId, trustedDeviceId, sessionName, sourceIdentity } = session;
  const { agentId, delegationId } = session;
  if (
    typeof id !== 'string' ||
    typeof tenantId !== 'string' ||
    typeof sessionId !== 'string' ||
    typeof sessionTenant !== 'string' ||
    (kind !== 'user' &&
      kind !== 'role' &&
      kind !== 'api-key' &&
      kind !== 'session-token' &&
      kind !== 'delegated')
  )
    throw new Error('The IAM server returned an unrecognized principal');
  const principal: IamPrincipal = {
    identity: { id, tenantId, name: typeof name === 'string' ? name : '' },
    session: {
      id: sessionId,
      tenantId: sessionTenant,
      kind,
      mfa: session.mfa === true,
      authenticatedAt: Number(session.authenticatedAt),
      expiresAt: Number(session.expiresAt),
    },
  };
  if (typeof email === 'string') principal.identity.email = email;
  if (identityKind === 'user' || identityKind === 'service' || identityKind === 'agent')
    principal.identity.kind = identityKind;
  if (typeof status === 'string') principal.identity.status = status;
  if (typeof method === 'string') principal.session.method = method as AuthMethod;
  if (typeof roleId === 'string') principal.session.roleId = roleId;
  if (typeof impersonatorId === 'string') principal.session.impersonatorId = impersonatorId;
  if (typeof trustedDeviceId === 'string') principal.session.trustedDeviceId = trustedDeviceId;
  // Copied only when present, so principals of credentials without them keep their exact keys.
  if (typeof sessionName === 'string') principal.session.sessionName = sessionName;
  if (typeof sourceIdentity === 'string') principal.session.sourceIdentity = sourceIdentity;
  if (typeof agentId === 'string') principal.session.agentId = agentId;
  if (typeof delegationId === 'string') principal.session.delegationId = delegationId;
  return principal;
}
/** A JSON copy of a session for the browser, without the stored token hash (`uniqueKey` repeats `tokenHash`). */
function plainSession<S>(session: S): S {
  const copy = JSON.parse(JSON.stringify(session)) as S;
  const inner = (copy as { session?: unknown } | null)?.session;
  if (inner && typeof inner === 'object') {
    delete (inner as Record<string, unknown>).uniqueKey;
    delete (inner as Record<string, unknown>).tokenHash;
  }
  return copy;
}

// Every code with which the server refuses a presented session: the request is treated as signed out.
const authenticationCodes = new Set([
  'UNAUTHENTICATED',
  'MFA_REQUIRED',
  'EMAIL_UNVERIFIED',
  'TENANT_INACTIVE',
  'TENANT_UNAVAILABLE',
  'INVALID_TENANT_TREE',
  'SESSION_NETWORK_MISMATCH',
  'IP_NOT_ALLOWED',
  'IP_BLOCKED',
]);
function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined;
}
function errorStatus(error: unknown): number {
  const status =
    error && typeof error === 'object' && 'status' in error ? Number(error.status) : NaN;
  return Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
}
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed';
}
/**
 * Errors whose code and message are meant for callers: the server's `IamError` (also what these helpers raise) and
 * the typed client's `IamClientError`. Matched by name so duplicate package copies still count. Anything else, such
 * as a database or file-system error with its own `code`, is rethrown rather than echoed.
 */
function isIamError(error: unknown): error is Error & { code: string } {
  return (
    error instanceof Error &&
    (error.name === 'IamError' || error.name === 'IamClientError') &&
    typeof (error as { code?: unknown }).code === 'string'
  );
}
/** True for Next's control-flow throws (`redirect`, `notFound`, `forbidden`, `unauthorized`), which must propagate. */
export function isNextControlError(error: unknown): boolean {
  const digest = error && typeof error === 'object' && 'digest' in error ? error.digest : undefined;
  return typeof digest === 'string' && /^(NEXT_|DYNAMIC_SERVER_USAGE)/.test(digest);
}
/** True for the errors `getSession` raises when there is no usable session. */
export function isAuthenticationError(error: unknown): boolean {
  const code = errorCode(error);
  return code !== undefined && authenticationCodes.has(code);
}
async function normalize(source: HeaderSource): Promise<Headers> {
  const resolved = await source;
  return resolved instanceof Headers ? resolved : new Headers(resolved);
}
function hasSessionCookie(headers: Headers): boolean {
  return (headers.get('cookie') ?? '')
    .split(';')
    .some((part) => /^\s*(__Host-)?better-iam\.session=./.test(part));
}
function urlPart(value: string, part: 'host' | 'origin'): string | undefined {
  try {
    return new URL(value)[part];
  } catch {
    return undefined;
  }
}
const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
function tenantOf(session: unknown): string | undefined {
  const inner = (session as { session?: { tenantId?: unknown } } | null)?.session;
  return typeof inner?.tenantId === 'string' ? inner.tenantId : undefined;
}
function withQuery(target: string, params: Record<string, string | undefined>): string {
  const entries = Object.entries(params).filter(
    (entry): entry is [string, string] => entry[1] !== undefined,
  );
  if (!entries.length) return target;
  const query = entries
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
  return `${target}${target.includes('?') ? '&' : '?'}${query}`;
}

/** Parses one `Set-Cookie` header into the name, decoded value, and options Next's `cookies().set` accepts. */
export function parseSetCookie(
  header: string,
): { name: string; value: string; options: CookieOptions } | undefined {
  const [pair, ...attributes] = header.split(';');
  const separator = pair?.indexOf('=') ?? -1;
  if (!pair || separator <= 0) return undefined;
  const name = pair.slice(0, separator).trim();
  let value = pair.slice(separator + 1).trim();
  try {
    value = decodeURIComponent(value);
  } catch {
    /* Keep the raw value when it is not percent-encoded. */
  }
  const options: CookieOptions = {};
  for (const attribute of attributes) {
    const [rawKey = '', ...rest] = attribute.split('=');
    const key = rawKey.trim().toLowerCase();
    const setting = rest.join('=').trim();
    if (key === 'httponly') options.httpOnly = true;
    else if (key === 'secure') options.secure = true;
    else if (key === 'path') options.path = setting;
    else if (key === 'domain') options.domain = setting;
    else if (key === 'max-age' && /^-?\d+$/.test(setting)) options.maxAge = Number(setting);
    else if (key === 'expires' && !Number.isNaN(Date.parse(setting)))
      options.expires = new Date(setting);
    else if (key === 'samesite') {
      const mode = setting.toLowerCase();
      if (mode === 'lax' || mode === 'strict' || mode === 'none') options.sameSite = mode;
    }
  }
  return { name, value, options };
}

/** Request headers forwarded from the incoming request when `client()` calls the IAM handler in process. */
const forwardedHeaders = [
  'cookie',
  'authorization',
  'user-agent',
  'accept-language',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  // A registered device's signed proof (verified by the server against the enrolled key and the session).
  'x-better-iam-device',
];

export interface AuthorizeSpec<Input> {
  action: string;
  /** The resource to check; defaults to the tenant itself (`iam/{tenantId}`). */
  resource?: (input: Input) => ResourceRef | Promise<ResourceRef>;
  /** The tenant to check in; defaults to the session's tenant. */
  tenantId?: (input: Input) => string | Promise<string>;
}
type RouteParams = Record<string, string | string[] | undefined>;
/** The second argument Next passes to App Router route handlers. */
export interface RouteContext<Params extends RouteParams> {
  params: Promise<Params>;
}
export interface RouteSpec<Session, Params extends RouteParams> {
  /** Checked after authentication and before `authorize`; a shortfall answers 403 with its code. */
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ session: Session; params: Params; request: Request }>;
}
export interface ApiRouteSpec<Params extends RouteParams> {
  /**
   * Applies to the credential's own session: API keys have no MFA, and their `authenticatedAt` is their creation;
   * assumed roles inherit both from the session that assumed them and never satisfy `mfa: 'fresh'`.
   */
  stepUp?: StepUpRequirement;
  /** The tenant defaults to the one the credential acts in (`principal.session.tenantId`). */
  authorize?: AuthorizeSpec<{ principal: IamPrincipal; params: Params; request: Request }>;
}
export interface ActionSpec<Session, Args extends unknown[]> {
  /** Checked after authentication and before `authorize`; a shortfall returns `{ ok: false }` with its code. */
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ session: Session; args: Args }>;
}
export interface PageProps {
  params?: Promise<RouteParams>;
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}
type ParamsOf<Props> = Props extends { params?: Promise<infer Params> } ? Params : RouteParams;
export interface PageSpec<Session, Params> {
  /** The path to come back to after sign-in; defaults to the middleware-forwarded path. */
  returnTo?: (params: Params) => string;
  /** Where signed-out visitors go instead of the login path. */
  loginRedirect?: string;
  /** Checked after sign-in and before `authorize`; a shortfall redirects to the step-up page with `?next=&reason=`. */
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ session: Session; params: Params }> & {
    /** Where denied visitors go; without it the denial throws (or calls `forbidden()` with `interrupts`). */
    redirectTo?: string;
  };
}

/** The part of a Node response the Pages Router client writes cookies to. */
export interface CookieResponse {
  getHeader(name: string): number | string | string[] | undefined;
  setHeader(name: string, value: string | string[]): unknown;
}
export interface PagesSpec<Session> {
  /** Where signed-out visitors go instead of the login path. */
  loginRedirect?: string;
  /** Checked after sign-in and before `authorize`; a shortfall redirects to the step-up page with `?next=&reason=`. */
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ session: Session; params: ParsedUrlQuery; query: ParsedUrlQuery }> & {
    /** Where denied visitors go; without it the page answers `notFound`. */
    redirectTo?: string;
  };
}
export interface PagesApiSpec<Session> {
  /** Checked after authentication and before `authorize`; a shortfall answers 403 with its code. */
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ session: Session; req: NextApiRequest }>;
}
function nodeHeaders(source: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const item of value) headers.append(name, item);
    else headers.set(name, value);
  }
  return headers;
}
function appendSetCookie(res: CookieResponse, issued: string[]): void {
  const existing = res.getHeader('set-cookie');
  const list =
    existing === undefined ? [] : Array.isArray(existing) ? existing : [String(existing)];
  res.setHeader('set-cookie', [...list, ...issued]);
}
function routeResponse(result: unknown): Response {
  if (result instanceof Response) return result;
  if (result === undefined) return new Response(null, { status: 204 });
  return Response.json(result, { headers: { 'cache-control': 'no-store' } });
}
/** The JSON error envelope for IAM failures; Next control flow and every other error are rethrown. */
function routeError(error: unknown): Response {
  if (isNextControlError(error) || !isIamError(error)) throw error;
  return Response.json(
    { error: { code: error.code, message: error.message } },
    { status: errorStatus(error), headers: { 'cache-control': 'no-store' } },
  );
}

/**
 * Server-side helpers for the App Router. Server components and route handlers read the session from the request
 * cookies, enforce with `require`, batch advisory decisions with `can`, and mount the IAM handler with `handlers()`.
 * `client()` is the typed API bound to the current request (cookies are kept in sync from server actions), and
 * `page`, `route`, and `action` wrap pages, route handlers, and server actions with authentication, step-up, and
 * authorization; `apiRoute` also admits API keys and assumed roles.
 */
export function createIamNext<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamNextOptions = {},
) {
  type Session = SessionOf<T>;
  const resolve = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  // Next's entry files are CommonJS; explicit .js specifiers resolve under Node ESM and bundlers alike.
  const nextHeaders = async () => {
    const mod = await import('next/headers.js');
    return {
      headers: mod.headers ?? mod.default.headers,
      cookies: mod.cookies ?? mod.default.cookies,
    };
  };
  const readHeaders =
    options.headers ??
    (async () => {
      const mod = await nextHeaders();
      const merged = new Headers(await mod.headers());
      // cookies() reflects cookies a server action just set, so a re-render after sign-in sees the new session.
      try {
        const jar = (await mod.cookies()).toString();
        if (jar) merged.set('cookie', jar);
        else merged.delete('cookie');
      } catch {
        /* Outside a request scope the header value stands. */
      }
      return merged;
    });
  const cookieStore =
    options.cookies ??
    (async (): Promise<CookieStore> => (await (await nextHeaders()).cookies()) as CookieStore);
  const navigation = async (name: 'redirect' | 'unauthorized' | 'forbidden' | 'notFound') => {
    const mod = (await import('next/navigation.js')) as unknown as Record<string, unknown> & {
      default?: Record<string, unknown>;
    };
    const fn = mod[name] ?? mod.default?.[name];
    if (typeof fn !== 'function')
      throw new Error(`next/navigation does not provide ${name}(); upgrade Next.js`);
    return fn as (...args: unknown[]) => never;
  };
  const redirectTo =
    options.redirect ??
    (async (url: string): Promise<never> => {
      (await navigation('redirect'))(url);
      throw new Error('redirect did not interrupt rendering');
    });
  const interrupt = async (name: 'unauthorized' | 'forbidden' | 'notFound'): Promise<never> => {
    const override = options[name];
    if (override) await override();
    else (await navigation(name))();
    throw new Error(`${name}() did not interrupt rendering`);
  };
  const credential = async (headers?: HeaderSource): Promise<CredentialInput> => ({
    headers: await normalize(headers ?? (await readHeaders())),
  });
  const loadSession = async (headers?: HeaderSource): Promise<Session | null> => {
    try {
      return (await (await resolve()).api.auth.getSession(await credential(headers))) as Session;
    } catch (error) {
      if (isAuthenticationError(error)) return null;
      throw error;
    }
  };
  const memoize =
    options.cache ??
    (typeof (React as { cache?: unknown }).cache === 'function'
      ? (React as unknown as { cache: <F>(fn: F) => F }).cache
      : undefined);
  const ambientSession = memoize ? memoize(() => loadSession()) : () => loadSession();
  const getSession = (headers?: HeaderSource): Promise<Session | null> =>
    headers === undefined ? ambientSession() : loadSession(headers);
  const currentPath = async (headers?: HeaderSource): Promise<string | undefined> => {
    const value = (await normalize(headers ?? (await readHeaders()))).get(pathnameHeader);
    const path = safeRedirectPath(value, '');
    return path || undefined;
  };
  /**
   * Where to return after sign-in. A request that still carries a session cookie reached a guard with a stale or
   * revoked session, so it always gets a `next` (`/` at worst): the middleware's `signedInRedirect` skips login
   * visits that have one, which is what breaks the stale-cookie redirect loop.
   */
  const returnPath = async (headers?: HeaderSource): Promise<string | undefined> => {
    const request = await normalize(headers ?? (await readHeaders()));
    const path = safeRedirectPath(request.get(pathnameHeader), '');
    if (path) return path;
    return hasSessionCookie(request) ? '/' : undefined;
  };
  const loginPath = options.loginPath ?? '/login';
  const clock = options.now ?? Date.now;
  const pendingStepUp = (session: unknown, requirement: StepUpRequirement | undefined) =>
    requirement ? checkStepUp(session, requirement, clock()) : null;
  /** Throws the coded step-up error (403) when the session falls short; route handlers and actions report it. */
  const assertStepUp = (session: unknown, requirement: StepUpRequirement | undefined): void => {
    const failure = pendingStepUp(session, requirement);
    if (failure) throw stepUpError(failure);
  };
  /** Where a page guard sends a session that must step up; without a step-up page the failure is thrown. */
  const stepUpDestination = (
    failure: StepUpFailure,
    target: string | undefined,
    next: string,
  ): string => {
    const path = target ?? options.stepUpPath;
    if (path === undefined) throw stepUpError(failure);
    return withQuery(path, { next, reason: failure.reason });
  };
  /**
   * The IAM handler's CSRF boundary, for wrapped route handlers: a state-changing request authenticated by the session
   * cookie (no Authorization header) must come from this application's host, the IAM origin, or `trustedOrigins`.
   */
  const assertCookieOrigin = async (
    method: string,
    headers: Headers,
    url?: string,
  ): Promise<void> => {
    if (safeMethods.has(method.toUpperCase()) || headers.has('authorization')) return;
    if (!hasSessionCookie(headers) || headers.get('sec-fetch-site') === 'same-origin') return;
    const origin = headers.get('origin');
    if (!origin) throw new IamError('CSRF_REJECTED', 'Cookie requests require Origin', 403);
    // An opaque `null` origin (sandboxed frames, redirects, no-referrer posts) equals the `.origin` of non-http
    // trusted entries such as `capacitor://localhost`, so it is refused before any comparison.
    if (origin === 'null') throw new IamError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
    const host = urlPart(origin, 'host');
    const ownHosts = [
      headers.get('x-forwarded-host')?.split(',')[0]?.trim(),
      headers.get('host'),
      url === undefined ? undefined : urlPart(url, 'host'),
    ];
    if (host !== undefined && ownHosts.includes(host)) return;
    const iam = await resolve();
    const trusted = [iam.endpoint?.origin, options.baseURL, ...(options.trustedOrigins ?? [])];
    if (trusted.some((entry) => entry !== undefined && urlPart(entry, 'origin') === origin)) return;
    throw new IamError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
  };

  const requireSession = async (
    input: {
      headers?: HeaderSource;
      redirectTo?: string;
      returnTo?: string;
      /** Extra assurance the session must have; see `StepUpRequirement`. */
      stepUp?: StepUpRequirement;
    } = {},
  ): Promise<Session> => {
    const session = await getSession(input.headers);
    if (session) {
      const failure = pendingStepUp(session, input.stepUp);
      if (!failure) return session;
      const next = input.returnTo ?? (await currentPath(input.headers)) ?? '/';
      return redirectTo(stepUpDestination(failure, input.stepUp?.redirectTo, next));
    }
    if (options.interrupts === true && input.redirectTo === undefined)
      return interrupt('unauthorized');
    const returnTo = input.returnTo ?? (await returnPath(input.headers));
    return redirectTo(withQuery(input.redirectTo ?? loginPath, { next: returnTo }));
  };
  const enforce = async (input: {
    tenantId: string;
    action: string;
    resource: ResourceRef;
    headers?: HeaderSource;
    redirectTo?: string;
    /** Route handlers and server actions report failures themselves: no redirects or interrupts. */
    plain?: boolean;
  }): Promise<void> => {
    const iam = await resolve();
    try {
      await iam.require({
        ...(await credential(input.headers)),
        tenantId: input.tenantId,
        action: input.action,
        resource: input.resource,
      });
    } catch (error) {
      if (input.plain) throw error;
      const unauthenticated = isAuthenticationError(error);
      const denied = errorCode(error) === 'ACCESS_DENIED';
      if (input.redirectTo && (unauthenticated || denied)) return redirectTo(input.redirectTo);
      if (options.interrupts === true && unauthenticated) return interrupt('unauthorized');
      if (options.interrupts && denied) return interrupt('forbidden');
      throw error;
    }
  };
  const authorizeWith = async <Input extends { session: Session } | { principal: IamPrincipal }>(
    spec: AuthorizeSpec<Input> | undefined,
    input: Input,
    headers: HeaderSource | undefined,
    mode: { redirectTo?: string; plain?: boolean } = {},
  ): Promise<void> => {
    if (!spec) return;
    const tenantId = spec.tenantId
      ? await spec.tenantId(input)
      : tenantOf('principal' in input ? input.principal : input.session);
    if (!tenantId) throw new IamError('INVALID_INPUT', 'No tenant to authorize in', 400);
    await enforce({
      tenantId,
      action: spec.action,
      resource: spec.resource ? await spec.resource(input) : { type: 'iam', id: tenantId },
      ...(headers === undefined ? {} : { headers }),
      ...(mode.redirectTo === undefined ? {} : { redirectTo: mode.redirectTo }),
      ...(mode.plain ? { plain: true } : {}),
    });
  };
  const lookupTenant = async (slug: string): Promise<TenantSummary | null> => {
    const iam = await resolve();
    if (!iam.api.tenants) throw new Error('This IAM server does not resolve tenant aliases');
    try {
      return await iam.api.tenants.lookup({ slug });
    } catch (error) {
      const code = errorCode(error);
      if (code === 'NOT_FOUND' || code === 'INVALID_INPUT') return null;
      throw error;
    }
  };

  /** Collects advisory checks for one request and answers them with as few `authorizeMany` calls as possible. */
  const newBatcher = () => {
    type Pending = {
      check: AuthorizeCheck;
      resolve: (allowed: boolean) => void;
      reject: (error: unknown) => void;
    };
    const answers = new Map<string, Promise<boolean>>();
    const queues = new Map<string, Pending[]>();
    let scheduled = false;
    const flush = async () => {
      scheduled = false;
      const batches = [...queues];
      queues.clear();
      try {
        const iam = await resolve();
        const caller = await credential();
        for (const [tenantId, pending] of batches)
          for (let start = 0; start < pending.length; start += 50) {
            const slice = pending.slice(start, start + 50);
            try {
              const { results } = await iam.authorizeMany({
                ...caller,
                tenantId,
                checks: slice.map((item) => item.check),
              });
              slice.forEach((item, index) => item.resolve(results[index]?.allowed ?? false));
            } catch (error) {
              if (errorCode(error) === undefined) throw error;
              for (const item of slice) item.resolve(false);
            }
          }
      } catch (error) {
        for (const [, pending] of batches) for (const item of pending) item.reject(error);
      }
    };
    return (tenantId: string, check: AuthorizeCheck): Promise<boolean> => {
      const key = JSON.stringify([tenantId, check.action, check.resource.type, check.resource.id]);
      let answer = answers.get(key);
      if (!answer) {
        answer = new Promise<boolean>((resolvePromise, rejectPromise) => {
          const queue = queues.get(tenantId) ?? [];
          queue.push({ check, resolve: resolvePromise, reject: rejectPromise });
          queues.set(tenantId, queue);
        });
        answers.set(key, answer);
        if (!scheduled) {
          scheduled = true;
          // A macrotask, not a microtask: sibling server components reach their checks after their own awaits.
          setTimeout(() => void flush(), 0);
        }
      }
      return answer;
    };
  };
  const requestBatcher = memoize ? memoize(newBatcher) : newBatcher;
  const allowed = async (
    action: string,
    resource?: ResourceRef,
    input: { tenantId?: string } = {},
  ): Promise<boolean> => {
    const tenantId = input.tenantId ?? tenantOf(await getSession());
    if (!tenantId) return false;
    return requestBatcher()(tenantId, {
      action,
      resource: resource ?? { type: 'iam', id: tenantId },
    });
  };
  /**
   * A typed client whose transport is `iam.handler` in this process: the incoming request's cookies and forwarding
   * headers go in, the server's `Set-Cookie` headers come out through `writeCookies`.
   */
  const inProcessClient = (
    incoming: () => Promise<Headers>,
    writeCookies: (setCookies: string[]) => Promise<void>,
  ): IamClient<T> => {
    const endpoint = async (request: Headers) => {
      const iam = await resolve();
      if (iam.endpoint) return iam.endpoint;
      if (options.baseURL)
        return {
          origin: new URL(options.baseURL).origin,
          basePath: options.basePath ?? '/api/iam',
        };
      const host = request.get('x-forwarded-host') ?? request.get('host');
      if (!host) throw new Error('Set baseURL: the IAM origin cannot be derived from this request');
      const protocol = request.get('x-forwarded-proto') ?? 'https';
      return { origin: `${protocol}://${host}`, basePath: options.basePath ?? '/api/iam' };
    };
    const fetcher = async (url: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
      const iam = await resolve();
      const request = await incoming();
      const { origin, basePath } = await endpoint(request);
      const target = new URL(url instanceof Request ? url.url : url);
      const headers = new Headers(init.headers);
      for (const name of forwardedHeaders) {
        const value = request.get(name);
        if (value !== null && !headers.has(name)) headers.set(name, value);
      }
      headers.set('origin', origin);
      // With organization addresses (`hosts`), the call keeps the host the visitor is on, so the server pins it to
      // that organization (and fills in its tenant ID) exactly as it would a browser call from the page.
      const visited = iam.hosts ? (request.get('x-forwarded-host') ?? request.get('host')) : null;
      const address =
        visited && /^[a-z0-9.-]+(:\d{1,5})?$/i.test(visited)
          ? `${new URL(origin).protocol}//${visited}`
          : origin;
      const response = await iam.handler(
        new Request(new URL(target.pathname.replace(/^\/api\/iam/, basePath), address), {
          method: init.method ?? 'POST',
          headers,
          ...(init.body === undefined || init.body === null ? {} : { body: init.body }),
        }),
      );
      const issued = response.headers.getSetCookie();
      if (issued.length) await writeCookies(issued);
      if (options.dispatchAfterResponse) backgroundWork().schedule();
      return response;
    };
    return createIamClient<T>({
      baseURL: 'http://better-iam.internal',
      fetch: fetcher as typeof fetch,
    });
  };

  let background: IamBackground | undefined;
  const backgroundWork = (): IamBackground =>
    (background ??= createBackground(
      resolve as unknown as () => Promise<BackgroundIam>,
      options.background,
    ));
  const requestClient = (input: { headers?: HeaderSource } = {}): IamClient<T> =>
    inProcessClient(
      async () => normalize(input.headers ?? (await readHeaders())),
      async (issued) => {
        const jar = await cookieStore();
        for (const header of issued) {
          const cookie = parseSetCookie(header);
          if (!cookie) continue;
          try {
            jar.set(cookie.name, cookie.value, cookie.options);
          } catch (error) {
            throw new Error(
              `Better IAM could not update the ${cookie.name} cookie; call this method from a server action or route handler (${errorMessage(error)})`,
            );
          }
        }
      },
    );
  const clearSessionCookie = async (): Promise<void> => {
    const iam = await resolve();
    const secure =
      iam.endpoint?.secure ??
      (options.baseURL ? new URL(options.baseURL).protocol === 'https:' : false);
    (await cookieStore()).set(sessionCookieName(secure), '', {
      httpOnly: true,
      secure,
      sameSite: 'lax',
      path: '/',
      maxAge: 0,
    });
  };

  return {
    credential,
    /** The current session, or null when the request carries no usable credential. Memoized per request. */
    getSession,
    /** The path the middleware forwarded for this request (`x-better-iam-pathname`), when present and safe. */
    currentPath,
    /**
     * The current session, or a redirect to the login path. `?next=` carries `returnTo`, or the middleware-forwarded
     * path when middleware passes `next`. With `interrupts`, a missing session calls `unauthorized()` instead.
     */
    requireSession,
    /** Enforces one action before rendering; denial redirects when `redirectTo` is given and throws otherwise. */
    require: enforce,
    /** Advisory decisions keyed `${action}@${type}/${id}`; every key is false when the request is not authenticated. */
    async can(input: {
      tenantId: string;
      checks: { action: string; resource?: ResourceRef }[];
      headers?: HeaderSource;
    }): Promise<Record<string, boolean>> {
      const checks = input.checks.map((check) => ({
        action: check.action,
        resource: check.resource ?? { type: 'iam', id: input.tenantId },
      }));
      const key = (check: AuthorizeCheck) =>
        `${check.action}@${check.resource.type}/${check.resource.id}`;
      try {
        const { results } = await (
          await resolve()
        ).authorizeMany({ ...(await credential(input.headers)), tenantId: input.tenantId, checks });
        return Object.fromEntries(results.map((result) => [key(result), result.allowed]));
      } catch (error) {
        if (errorCode(error) !== undefined)
          return Object.fromEntries(checks.map((check) => [key(check), false]));
        throw error;
      }
    },
    /**
     * One advisory decision for the current request, batched: every `allowed()` call made while a render is in
     * flight joins one `authorizeMany` (deduplicated, 50 checks per round trip), and repeated checks reuse the
     * answer for the rest of the request. The tenant defaults to the session's; signed-out requests get false.
     */
    allowed,
    /**
     * Server component: renders `children` when the current session may perform the action, `fallback` otherwise.
     * `<iamNext.Can action="projects:manage" resource={{ type: 'project', id }}>...</iamNext.Can>`. Checks from
     * sibling components share one batched `authorizeMany`. Advisory only: enforce the mutation itself.
     */
    async Can(props: {
      action: string;
      resource?: ResourceRef;
      tenantId?: string;
      children?: ReactNode;
      fallback?: ReactNode;
    }): Promise<ReactNode> {
      const permitted = await allowed(
        props.action,
        props.resource,
        props.tenantId === undefined ? {} : { tenantId: props.tenantId },
      );
      return permitted ? (props.children ?? null) : (props.fallback ?? null);
    } /**
     * A short-lived signed assertion about the current session for a downstream service, from a server component or
     * route handler; the caller needs `iam:assertions:create` on `iam/{audience}`.
     */,
    async assertion(input: AssertionInput & { headers?: HeaderSource }): Promise<AssertionOf<T>> {
      const iam = await resolve();
      if (!iam.api.assertions) throw new Error('This IAM server does not issue assertions');
      const { headers, ...rest } = input;
      return (await iam.api.assertions.issue(await credential(headers), rest)) as AssertionOf<T>;
    },
    /**
     * The session as plain JSON for a client component's `IamProvider initialSession`, or null when signed out. The
     * session's stored token hash is left out.
     */
    async sessionForClient(headers?: HeaderSource): Promise<Session | null> {
      const session = await getSession(headers);
      return session === null ? null : plainSession(session);
    },
    /** Resolves an organization alias (`tenants.lookup`); null when it does not exist or is inactive. */
    tenant: lookupTenant,
    /**
     * For `/[org]/...` routes: resolves the alias (unknown aliases call `notFound()`) and requires a session in that
     * tenant. Visitors signed out, or signed in to another organization, go to the login path with `?org=` and `?next=`.
     */
    async requireTenantSession(input: {
      slug: string;
      headers?: HeaderSource;
      returnTo?: string;
      redirectTo?: string;
    }): Promise<{ tenant: TenantSummary; session: Session }> {
      const tenant = await lookupTenant(input.slug);
      if (!tenant) return interrupt('notFound');
      const session = await getSession(input.headers);
      if (session && tenantOf(session) === tenant.tenantId) return { tenant, session };
      const returnTo = input.returnTo ?? (await returnPath(input.headers));
      return redirectTo(
        withQuery(input.redirectTo ?? loginPath, { org: tenant.slug, next: returnTo }),
      );
    },
    /**
     * The typed client bound to the current request, calling the IAM handler in process (no network hop). Cookies the
     * server issues (sign-in, MFA, sign-out, trusted devices) are written through `cookies()`, so server actions can
     * sign people in and out without client JavaScript. Use it from server actions and route handlers; server
     * components may only call methods that do not change cookies.
     */
    client: requestClient,
    /**
     * Expires the session cookie in this response (server actions and route handlers). Sign-out calls it when the
     * server no longer knows the presented session, so a stale cookie does not linger.
     */
    clearSessionCookie,
    /**
     * Drop-in server actions for complete sign-in (password, MFA, enrollment, recovery and emailed codes), step-up,
     * sign-out, password reset, sign-up, email verification, and invitations, bound to this request context. Export
     * them from a `'use server'` module: `export const signIn = auth.signIn;`.
     */
    authActions(actionOptions: AuthActionsOptions = {}): AuthActions {
      return createAuthActions(
        { client: () => requestClient(), tenant: lookupTenant, clearSessionCookie },
        {
          loginPath,
          afterSignOut: loginPath,
          ...(options.redirect === undefined ? {} : { redirect: options.redirect }),
          ...actionOptions,
        },
      );
    },
    /**
     * Outbox and event dispatch for this instance: `dispatch()` now, `schedule()` after the response, and `cron()`,
     * a route handler for a scheduler (`Authorization: Bearer <CRON_SECRET>`).
     */
    get background(): IamBackground {
      return backgroundWork();
    },
    /**
     * Wraps a page or layout: requires a session (redirecting to the login path with `?next=`), optionally a step-up
     * (redirecting to the step-up page with `?next=&reason=`), optionally enforces an action, then renders with the
     * session and resolved params.
     *
     * ```tsx
     * export default iamNext.page(
     *   async (props: { params: Promise<{ id: string }> }, { session, params }) => <Project id={params.id} />,
     *   { authorize: { action: 'projects:read', resource: ({ params }) => ({ type: 'project', id: params.id }) } },
     * );
     * ```
     */
    page<Props extends PageProps, Result>(
      render: (props: Props, input: { session: Session; params: ParamsOf<Props> }) => Result,
      spec: PageSpec<Session, NoInfer<ParamsOf<Props>>> = {},
    ): (props: Props) => Promise<Awaited<Result>> {
      if (spec.stepUp) validateStepUp(spec.stepUp);
      return async (props: Props): Promise<Awaited<Result>> => {
        const params = ((await props.params) ?? {}) as ParamsOf<Props>;
        const session = await requireSession({
          ...(spec.returnTo ? { returnTo: spec.returnTo(params) } : {}),
          ...(spec.loginRedirect ? { redirectTo: spec.loginRedirect } : {}),
          ...(spec.stepUp ? { stepUp: spec.stepUp } : {}),
        });
        await authorizeWith(
          spec.authorize,
          { session, params },
          undefined,
          spec.authorize?.redirectTo === undefined ? {} : { redirectTo: spec.authorize.redirectTo },
        );
        const output: Awaited<Result> = await render(props, { session, params });
        return output;
      };
    },
    /**
     * Wraps an App Router route handler: authenticates a user session from the request (cookie or bearer session
     * token; use `apiRoute` for API keys and assumed roles), optionally requires a step-up and enforces an action,
     * and maps IAM failures (`IamError`, `IamClientError`) to the JSON error envelope with their status; other errors
     * are rethrown. Cookie-authenticated requests other than GET, HEAD, and OPTIONS must come from this application's
     * origin (`Origin` or `Sec-Fetch-Site: same-origin`) or `trustedOrigins`, as the IAM handler requires, or answer
     * 403 `CSRF_REJECTED` / `UNTRUSTED_ORIGIN`. Non-Response results are returned as JSON; `undefined` answers 204.
     */
    route<Params extends RouteParams = RouteParams>(
      handler: (
        request: Request,
        input: { session: Session; params: Params },
      ) => unknown | Promise<unknown>,
      spec: RouteSpec<Session, NoInfer<Params>> = {},
    ): (request: Request, context: RouteContext<Params>) => Promise<Response> {
      if (spec.stepUp) validateStepUp(spec.stepUp);
      return async (request, context) => {
        try {
          await assertCookieOrigin(request.method, request.headers, request.url);
          const params = ((await context?.params) ?? {}) as Params;
          const iam = await resolve();
          const session = (await iam.api.auth.getSession({ headers: request.headers })) as Session;
          assertStepUp(session, spec.stepUp);
          await authorizeWith(spec.authorize, { session, params, request }, request.headers, {
            plain: true,
          });
          return routeResponse(await handler(request, { session, params }));
        } catch (error) {
          return routeError(error);
        }
      };
    },
    /**
     * Wraps an App Router route handler for machine callers too: any credential the server accepts (user sessions,
     * bearer API keys, assumed-role sessions) reaches `handler` as a sanitized `principal`. Step-up, authorization,
     * the origin check, and responses work as in `route()`; the authorization tenant defaults to the one the credential
     * acts in.
     *
     * ```ts
     * export const POST = iamNext.apiRoute(async (request, { principal }) => ({ by: principal.identity.id }), {
     *   authorize: { action: 'reports:create' },
     * });
     * ```
     */
    apiRoute<Params extends RouteParams = RouteParams>(
      handler: (
        request: Request,
        input: { principal: IamPrincipal; params: Params },
      ) => unknown | Promise<unknown>,
      spec: ApiRouteSpec<NoInfer<Params>> = {},
    ): (request: Request, context: RouteContext<Params>) => Promise<Response> {
      if (spec.stepUp) validateStepUp(spec.stepUp);
      return async (request, context) => {
        try {
          await assertCookieOrigin(request.method, request.headers, request.url);
          const params = ((await context?.params) ?? {}) as Params;
          const iam = await resolve();
          if (!iam.authenticate)
            throw new Error(
              'apiRoute() needs an IAM instance with authenticate(); pass the betterIam() instance',
            );
          const authenticated = await iam.authenticate({ headers: request.headers });
          assertStepUp(authenticated.session, spec.stepUp);
          const principal = toPrincipal(authenticated);
          await authorizeWith(spec.authorize, { principal, params, request }, request.headers, {
            plain: true,
          });
          return routeResponse(await handler(request, { principal, params }));
        } catch (error) {
          return routeError(error);
        }
      };
    },
    /**
     * Wraps a server action: requires a session, optionally a step-up, optionally enforces an action, and returns an
     * `ActionResult` so IAM failures (`UNAUTHENTICATED`, `RECENT_AUTH_REQUIRED`, `ACCESS_DENIED`, validation codes)
     * reach the form instead of an error boundary; `fn` reports its own failures the same way by throwing an
     * `IamError`. Other errors, and `redirect()` or other Next control flow thrown by `fn`, propagate.
     */
    action<Args extends unknown[], Result>(
      fn: (session: Session, ...args: Args) => Result | Promise<Result>,
      spec: ActionSpec<Session, NoInfer<Args>> = {},
    ): (...args: Args) => Promise<ActionResult<Awaited<Result>>> {
      if (spec.stepUp) validateStepUp(spec.stepUp);
      return async (...args) => {
        try {
          const session = await getSession();
          if (!session)
            return {
              ok: false,
              error: { code: 'UNAUTHENTICATED', message: 'Sign in to continue' },
            };
          assertStepUp(session, spec.stepUp);
          await authorizeWith(spec.authorize, { session, args }, undefined, { plain: true });
          return { ok: true, data: await fn(session, ...args) };
        } catch (error) {
          if (isNextControlError(error) || !isIamError(error)) throw error;
          return { ok: false, error: { code: error.code, message: error.message } };
        }
      };
    },
    /**
     * Pages Router support: `getServerSideProps` and API route wrappers, a request-bound client that writes cookies
     * to the API response, and the IAM handler for `pages/api/iam/[...path].ts`.
     */
    pages: {
      /** The session for a Pages Router request, or null. */
      getSession: (req: { headers: IncomingHttpHeaders }): Promise<Session | null> =>
        loadSession(nodeHeaders(req.headers)),
      /** The typed client bound to an API route request; issued cookies are appended to `res`. */
      client(req: { headers: IncomingHttpHeaders }, res: CookieResponse): IamClient<T> {
        return inProcessClient(
          async () => nodeHeaders(req.headers),
          async (issued) => appendSetCookie(res, issued),
        );
      },
      /**
       * `getServerSideProps` that requires a session (redirecting to the login path with `?next=`), optionally a
       * step-up (redirecting to the step-up page with `?next=&reason=`), optionally enforces an action (denials
       * answer `notFound`, or redirect to `authorize.redirectTo`), runs `gssp`, and adds the session to the page
       * props as JSON without its token hash.
       */
      withSession<Props extends Record<string, unknown> = Record<string, never>>(
        gssp?: (
          context: GetServerSidePropsContext,
          input: { session: Session },
        ) => GetServerSidePropsResult<Props> | Promise<GetServerSidePropsResult<Props>>,
        spec: PagesSpec<Session> = {},
      ): (
        context: GetServerSidePropsContext,
      ) => Promise<GetServerSidePropsResult<Props & { session: Session }>> {
        if (spec.stepUp) validateStepUp(spec.stepUp);
        return async (context) => {
          const headers = nodeHeaders(context.req.headers);
          const session = await loadSession(headers);
          if (!session) {
            const next = safeRedirectPath(context.resolvedUrl, '') || undefined;
            return {
              redirect: {
                destination: withQuery(spec.loginRedirect ?? loginPath, { next }),
                permanent: false,
              },
            };
          }
          const failure = pendingStepUp(session, spec.stepUp);
          if (failure) {
            const next = safeRedirectPath(context.resolvedUrl, '') || '/';
            return {
              redirect: {
                destination: stepUpDestination(failure, spec.stepUp?.redirectTo, next),
                permanent: false,
              },
            };
          }
          if (spec.authorize) {
            try {
              await authorizeWith(
                spec.authorize,
                { session, params: context.params ?? {}, query: context.query },
                headers,
                { plain: true },
              );
            } catch (error) {
              if (errorCode(error) !== 'ACCESS_DENIED') throw error;
              return spec.authorize.redirectTo
                ? { redirect: { destination: spec.authorize.redirectTo, permanent: false } }
                : { notFound: true };
            }
          }
          const plain = plainSession(session);
          if (!gssp) return { props: { session: plain } as Props & { session: Session } };
          const result = await gssp(context, { session });
          if (!('props' in result)) return result;
          return { props: { ...(await result.props), session: plain } };
        };
      },
      /**
       * Wraps a Pages Router API route: authenticates a user session from the request (cookie or bearer session
       * token), optionally requires a step-up and enforces an action, and answers IAM failures with the JSON error
       * envelope; other errors are rethrown. Cookie-authenticated mutations get the same origin check as `route()`.
       * Results are sent as JSON unless the handler already responded; `undefined` answers 204.
       */
      api<Result>(
        handler: (
          req: NextApiRequest,
          res: NextApiResponse,
          input: { session: Session },
        ) => Result | Promise<Result>,
        spec: PagesApiSpec<Session> = {},
      ): (req: NextApiRequest, res: NextApiResponse) => Promise<void> {
        if (spec.stepUp) validateStepUp(spec.stepUp);
        return async (req, res) => {
          try {
            const headers = nodeHeaders(req.headers);
            await assertCookieOrigin(req.method ?? 'GET', headers);
            const session = (await (await resolve()).api.auth.getSession({ headers })) as Session;
            assertStepUp(session, spec.stepUp);
            await authorizeWith(spec.authorize, { session, req }, headers, { plain: true });
            const result = await handler(req, res, { session });
            if (res.headersSent || res.writableEnded) return;
            res.setHeader('cache-control', 'no-store');
            if (result === undefined) res.status(204).end();
            else res.status(200).json(result);
          } catch (error) {
            if (!isIamError(error) || isNextControlError(error) || res.headersSent) throw error;
            res.setHeader('cache-control', 'no-store');
            res
              .status(errorStatus(error))
              .json({ error: { code: error.code, message: error.message } });
          }
        };
      },
      /**
       * The IAM HTTP API for `pages/api/iam/[...path].ts`: `export default iamNext.pages.handler()`. Bodies Next has
       * already parsed are re-encoded, so `bodyParser` can stay on; disable it for byte-exact protocol callbacks.
       */
      handler(): (req: NextApiRequest, res: NextApiResponse) => Promise<void> {
        return async (req, res) => {
          const iam = await resolve();
          const headers = nodeHeaders(req.headers);
          const host = headers.get('x-forwarded-host') ?? headers.get('host') ?? 'localhost';
          const origin =
            iam.endpoint?.origin ??
            (options.baseURL
              ? new URL(options.baseURL).origin
              : `${headers.get('x-forwarded-proto') ?? 'http'}://${host}`);
          const method = req.method ?? 'GET';
          let body: Uint8Array | string | undefined;
          if (method !== 'GET' && method !== 'HEAD') {
            if (req.body !== undefined && req.body !== null && req.body !== '') {
              const type = headers.get('content-type') ?? '';
              body =
                typeof req.body === 'string' || req.body instanceof Uint8Array
                  ? req.body
                  : type.startsWith('application/x-www-form-urlencoded')
                    ? new URLSearchParams(req.body as Record<string, string>).toString()
                    : JSON.stringify(req.body);
            } else {
              const chunks: Uint8Array[] = [];
              let size = 0;
              for await (const chunk of req as AsyncIterable<Uint8Array | string>) {
                const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk;
                size += bytes.length;
                if (size > 2097152) {
                  res.status(413).end('Request too large');
                  return;
                }
                chunks.push(bytes);
              }
              body = Buffer.concat(chunks);
            }
            headers.delete('content-length');
          }
          const response = await iam.handler(
            new Request(new URL(req.url ?? '/', origin), {
              method,
              headers,
              ...(body === undefined ? {} : { body: body as BodyInit }),
            }),
          );
          res.statusCode = response.status;
          response.headers.forEach((value, key) => {
            if (key !== 'set-cookie') res.setHeader(key, value);
          });
          const cookies = response.headers.getSetCookie();
          if (cookies.length) res.setHeader('set-cookie', cookies);
          res.end(Buffer.from(await response.arrayBuffer()));
          if (options.dispatchAfterResponse && method === 'POST') backgroundWork().schedule();
        };
      },
    },
    /**
     * Route handlers for `app/api/iam/[...path]/route.ts`: `export const { GET, POST, OPTIONS } = iamNext.handlers();`.
     * GET serves the operational `/health` and `/metrics` endpoints. With `dispatchAfterResponse`, every POST
     * schedules outbox and event dispatch after the response.
     */
    handlers() {
      const handle = async (request: Request): Promise<Response> => {
        const response = await (await resolve()).handler(request);
        if (options.dispatchAfterResponse && request.method === 'POST') backgroundWork().schedule();
        return response;
      };
      return { GET: handle, POST: handle, OPTIONS: handle };
    },
  };
}
export type IamNext<T extends IamLike> = ReturnType<typeof createIamNext<T>>;
