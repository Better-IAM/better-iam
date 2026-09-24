import type { CredentialInput } from '@better-iam/core';
import { createIamClient, type IamClient } from '@better-iam/client';

/** The server surface the middleware uses; a `betterIam()` instance satisfies it. */
export interface IamLike {
  api: {
    auth: {
      getSession(credential: CredentialInput): Promise<unknown>;
      signOut(credential: CredentialInput): Promise<unknown>;
    };
    assertions?: {
      issue(credential: CredentialInput, input: AssertionInput): Promise<unknown>;
    };
  };
  handler(request: Request): Promise<Response>;
  /** Node transport; serves node-only protocol mounts (the OAuth provider) too. */
  nodeHandler?(req: never, res: never): Promise<unknown>;
  require(
    request: CredentialInput & { tenantId: string; action: string; resource: ResourceRef },
  ): Promise<void>;
  authorizeMany(
    request: CredentialInput & { tenantId: string; checks: AuthorizeCheck[] },
  ): Promise<{ results: AuthorizeResult[] }>;
  listAccessible?(
    request: CredentialInput & {
      tenantId: string;
      action: string;
      type: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<unknown>;
  /** Query planning: which resources of a type the caller may act on, as a filter (`iam.planResources`). */
  planResources?(
    request: CredentialInput & { tenantId: string; action: string; type: string },
  ): Promise<unknown>;
  endpoint?: { origin: string; basePath: string; secure?: boolean };
  /** Organization sign-in addresses; when present, in-process calls keep the visitor's host so they are pinned. */
  hosts?: { resolve(host: string): Promise<unknown> };
}
export interface ResourceRef {
  type: string;
  id: string;
}
export interface AuthorizeCheck {
  action: string;
  resource: ResourceRef;
}
export interface AuthorizeResult extends AuthorizeCheck {
  allowed: boolean;
  reason: string;
}
export interface AssertionInput {
  tenantId: string;
  audience: string;
  ttlSeconds?: number;
  claims?: Record<string, unknown>;
}
export type SessionOf<T extends IamLike> = Awaited<ReturnType<T['api']['auth']['getSession']>>;
export type AssertionOf<T extends IamLike> = T['api'] extends {
  assertions: { issue(...args: never[]): infer Result };
}
  ? Awaited<Result>
  : unknown;
export type AccessibleOf<T extends IamLike> = T extends {
  listAccessible(...args: never[]): infer Result;
}
  ? Awaited<Result>
  : never;
export type PlanOf<T extends IamLike> = T extends {
  planResources(...args: never[]): infer Result;
}
  ? Awaited<Result>
  : never;
type MaybePromise<T> = T | Promise<T>;

/**
 * Extra assurance a session must show. `mfa: true` needs a session that completed MFA; `'fresh'` also refuses
 * remembered devices, impersonation, assumed roles, and API keys. `maxAgeMs` needs a recent sign-in.
 */
export interface StepUpRequirement {
  mfa?: boolean | 'fresh';
  maxAgeMs?: number;
}
export interface StepUpFailure {
  code: 'MFA_REQUIRED' | 'RECENT_AUTH_REQUIRED' | 'IMPERSONATION_RESTRICTED';
  reason: 'mfa' | 'recent' | 'impersonation';
  message: string;
  status: 403;
}

/**
 * A refusal raised by the request helpers and guards, with the IAM `code` and HTTP `status`. `reason` is set for
 * step-up failures (`mfa`, `recent`, `impersonation`). Framework adapters turn it into the IAM JSON error envelope or,
 * for page navigations, a redirect to the login / step-up page.
 */
export class IamRequestError extends Error {
  readonly code: string;
  readonly status: number;
  readonly reason: StepUpFailure['reason'] | undefined;
  constructor(code: string, message: string, status: number, reason?: StepUpFailure['reason']) {
    super(message);
    this.name = 'IamRequestError';
    this.code = code;
    this.status = status;
    this.reason = reason;
  }
}

const authenticationCodes = new Set([
  'UNAUTHENTICATED',
  'MFA_REQUIRED',
  'EMAIL_UNVERIFIED',
  'TENANT_INACTIVE',
  'TENANT_UNAVAILABLE',
]);
export function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined;
}
export function errorStatus(error: unknown): number | undefined {
  return error && typeof error === 'object' && 'status' in error && typeof error.status === 'number'
    ? error.status
    : undefined;
}
/** True for the errors `getSession` raises when there is no usable session. */
export function isAuthenticationError(error: unknown): boolean {
  const code = errorCode(error);
  return code !== undefined && authenticationCodes.has(code);
}
/** True for any error carrying an IAM code and an HTTP status (server `IamError`, client errors, `IamRequestError`). */
export function isIamRefusal(error: unknown): error is Error & { code: string; status: number } {
  return (
    error instanceof Error && errorCode(error) !== undefined && errorStatus(error) !== undefined
  );
}

/** A same-site relative path safe to redirect to, or `fallback`. Refuses schemes, `//host`, and backslash tricks. */
export function safeRedirectPath(value: string | null | undefined, fallback = '/'): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u001f]/.test(value))
    return fallback;
  try {
    const url = new URL(value, 'http://better-iam.invalid');
    if (url.origin !== 'http://better-iam.invalid') return fallback;
    const path = `${url.pathname}${url.search}${url.hash}`;
    return path.startsWith('//') ? fallback : path;
  } catch {
    return fallback;
  }
}
/** Appends query parameters, skipping undefined values. */
export function withQuery(target: string, params: Record<string, string | undefined>): string {
  const entries = Object.entries(params).filter(
    (entry): entry is [string, string] => entry[1] !== undefined,
  );
  if (!entries.length) return target;
  return `${target}${target.includes('?') ? '&' : '?'}${new URLSearchParams(entries).toString()}`;
}
/** True when `pathname` is `prefix` or below it on a segment boundary. */
export function underPath(pathname: string, prefix: string): boolean {
  const base = prefix.endsWith('/') && prefix !== '/' ? prefix.slice(0, -1) : prefix;
  return base === '/' || pathname === base || pathname.startsWith(`${base}/`);
}
/** The tenant a session acts in. */
export function tenantOf(session: unknown): string | undefined {
  const inner = (session as { session?: { tenantId?: unknown } } | null)?.session;
  return typeof inner?.tenantId === 'string' ? inner.tenantId : undefined;
}

/**
 * Checks a session against a step-up requirement; null when it qualifies. Accepts the `getSession` result or its
 * inner session record. Impersonated sessions always fail a recency requirement, as the server's own check does.
 */
export function checkStepUp(
  session: unknown,
  requirement: StepUpRequirement,
  now: number = Date.now(),
): StepUpFailure | null {
  const { mfa, maxAgeMs } = requirement;
  if (mfa !== undefined && typeof mfa !== 'boolean' && mfa !== 'fresh')
    throw new TypeError("stepUp.mfa must be true, false, or 'fresh'");
  if (
    maxAgeMs !== undefined &&
    (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs <= 0)
  )
    throw new TypeError('stepUp.maxAgeMs must be a positive, finite number of milliseconds');
  const outer = session && typeof session === 'object' ? (session as { session?: unknown }) : {};
  const record = (
    outer.session && typeof outer.session === 'object' ? outer.session : outer
  ) as Record<string, unknown>;
  const failure = (
    code: StepUpFailure['code'],
    reason: StepUpFailure['reason'],
    message: string,
  ): StepUpFailure => ({ code, reason, message, status: 403 });
  const impersonated = Boolean(record.impersonatorId) || record.method === 'impersonation';
  if (impersonated && (maxAgeMs !== undefined || mfa === 'fresh'))
    return failure(
      'IMPERSONATION_RESTRICTED',
      'impersonation',
      'This operation is unavailable while impersonating a member',
    );
  if (mfa && record.mfa !== true)
    return failure('MFA_REQUIRED', 'mfa', 'Multi-factor authentication is required');
  if (mfa === 'fresh') {
    if (record.trustedDeviceId)
      return failure('MFA_REQUIRED', 'mfa', 'Verify your second factor again to continue');
    if (record.kind !== 'user' || record.sourceSessionId)
      return failure(
        'MFA_REQUIRED',
        'mfa',
        'This credential cannot show a fresh second factor; use a signed-in session',
      );
  }
  if (maxAgeMs !== undefined) {
    const at = record.authenticatedAt;
    if (typeof at !== 'number' || at > now || !(now - at <= maxAgeMs))
      return failure('RECENT_AUTH_REQUIRED', 'recent', 'Reauthenticate to perform this operation');
  }
  return null;
}

/** Splits a `Cookie` header into name/value pairs (values left encoded). */
export function parseCookieHeader(header: string | null | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    if (name && !cookies.has(name)) cookies.set(name, part.slice(separator + 1).trim());
  }
  return cookies;
}
/** The name, raw value, and whether a `Set-Cookie` header deletes the cookie (`Max-Age=0` or a past `Expires`). */
export function setCookieSummary(
  header: string,
  now: number = Date.now(),
): { name: string; value: string; deleted: boolean } | undefined {
  const [pair, ...attributes] = header.split(';');
  const separator = pair?.indexOf('=') ?? -1;
  if (!pair || separator <= 0) return undefined;
  let deleted = false;
  for (const attribute of attributes) {
    const [key = '', ...rest] = attribute.split('=');
    const setting = rest.join('=').trim();
    const name = key.trim().toLowerCase();
    if (name === 'max-age' && /^-?\d+$/.test(setting) && Number(setting) <= 0) deleted = true;
    if (name === 'expires' && Date.parse(setting) <= now) deleted = true;
  }
  return {
    name: pair.slice(0, separator).trim(),
    value: pair.slice(separator + 1).trim(),
    deleted,
  };
}

/** What a framework adapter provides for one request. */
export interface RequestBinding {
  /** The incoming request's URL (used for the in-process client's origin when the instance has no `endpoint`). */
  url: URL;
  /** The incoming request's headers. */
  headers: Headers;
  /** Appends one `Set-Cookie` header to the outgoing response. */
  setCookie(header: string): void;
}

/** Request headers forwarded when the in-process client calls the IAM handler. */
const forwardedHeaders = [
  'authorization',
  'user-agent',
  'accept-language',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'x-request-id',
  // A registered device's signed proof (verified by the server against the enrolled key and the session).
  'x-better-iam-device',
];
const sessionCookies = ['better-iam.session', '__Host-better-iam.session'];

/**
 * The per-request helpers every framework adapter exposes (`req.iam`, `c.get('iam')`, `request.iam`). Sessions and
 * decisions are memoized for the request, and cookies the in-process client receives count for later calls.
 */
export interface IamRequest<T extends IamLike> {
  /** The current session, or null when the request carries no usable credential. */
  getSession(): Promise<SessionOf<T> | null>;
  /** The current session; throws `IamRequestError` 401 when signed out, 403 with a `reason` when it must step up. */
  requireSession(options?: { stepUp?: StepUpRequirement }): Promise<SessionOf<T>>;
  /** Enforces one action (default resource: the tenant); throws the server's refusal (401/403/429). */
  require(action: string, resource?: ResourceRef, options?: { tenantId?: string }): Promise<void>;
  /** One advisory decision; checks made in the same tick share one `authorizeMany` call. False when signed out. */
  can(action: string, resource?: ResourceRef, options?: { tenantId?: string }): Promise<boolean>;
  /** Advisory decisions for several checks; every check is denied (`UNAUTHENTICATED`) when signed out. */
  authorize(
    checks: { action: string; resource?: ResourceRef }[],
    options?: { tenantId?: string },
  ): Promise<AuthorizeResult[]>;
  /** The registered resources of a managed type the caller may act on. */
  listAccessible(input: {
    action: string;
    type: string;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<AccessibleOf<T>>;
  /**
   * Which resources of a type the caller may perform an action on, as a filter for your own query (compile it with
   * `filterToSql`, `filterToPrisma` or `filterToMongo` from `@better-iam/core`). Plans `never` when signed out.
   */
  plan(input: { action: string; type: string; tenantId?: string }): Promise<PlanOf<T>>;
  /** A short-lived signed assertion about the caller for a downstream service. */
  assertion(input: AssertionInput): Promise<AssertionOf<T>>;
  /** A typed client whose transport is `iam.handler` in this process; `Set-Cookie` answers go on this response. */
  readonly client: IamClient<T>;
  /** The credential for direct `iam.api.*` calls: this request's headers with cookies set during the request. */
  credential(): CredentialInput;
  /** Ends the session on the server and clears its cookie; never throws for an already-dead session. */
  signOut(): Promise<void>;
}

export interface RequestHelperOptions {
  /** Where the IAM HTTP API is served; defaults to the instance's `endpoint.basePath`, else `/api/iam`. */
  basePath?: string;
  now?: () => number;
}

/** Builds the per-request helpers over a framework's request and response. Framework adapters call this once per request. */
export function createRequestHelpers<T extends IamLike>(
  resolveIam: () => Promise<T>,
  binding: RequestBinding,
  options: RequestHelperOptions = {},
): IamRequest<T> {
  type Session = SessionOf<T>;
  const clock = options.now ?? Date.now;
  // Cookies set (or deleted) during this request override the incoming header for later calls.
  const overrides = new Map<string, string | null>();
  let session: Promise<Session | null> | undefined;
  let queue: {
    tenantId: string;
    check: AuthorizeCheck;
    done(allowed: boolean): void;
    fail(error: unknown): void;
  }[] = [];
  const answers = new Map<string, Promise<boolean>>();
  const forget = () => {
    session = undefined;
    answers.clear();
  };
  const headers = (): Headers => {
    const merged = new Headers(binding.headers);
    if (!overrides.size) return merged;
    const jar = parseCookieHeader(binding.headers.get('cookie'));
    for (const [name, value] of overrides) {
      if (value === null) jar.delete(name);
      else jar.set(name, value);
    }
    const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    if (cookie) merged.set('cookie', cookie);
    else merged.delete('cookie');
    return merged;
  };
  const credential = (): CredentialInput => ({ headers: headers() });
  const setCookie = (header: string) => {
    binding.setCookie(header);
    const summary = setCookieSummary(header, clock());
    if (summary) overrides.set(summary.name, summary.deleted ? null : summary.value);
  };
  const getSession = (): Promise<Session | null> =>
    (session ??= (async (): Promise<Session | null> => {
      try {
        return (await (await resolveIam()).api.auth.getSession(credential())) as Session;
      } catch (error) {
        if (isAuthenticationError(error)) return null;
        throw error;
      }
    })());
  const tenantFor = async (explicit: string | undefined): Promise<string | undefined> =>
    explicit ?? tenantOf(await getSession());
  const flush = async () => {
    const batch = queue;
    queue = [];
    const byTenant = new Map<string, typeof batch>();
    for (const item of batch)
      byTenant.set(item.tenantId, [...(byTenant.get(item.tenantId) ?? []), item]);
    let iam: T;
    try {
      iam = await resolveIam();
    } catch (error) {
      for (const item of batch) item.fail(error);
      return;
    }
    const caller = credential();
    for (const [tenantId, items] of byTenant)
      for (let start = 0; start < items.length; start += 50) {
        const slice = items.slice(start, start + 50);
        try {
          const { results } = await iam.authorizeMany({
            ...caller,
            tenantId,
            checks: slice.map((item) => item.check),
          });
          slice.forEach((item, index) => item.done(results[index]?.allowed ?? false));
        } catch (error) {
          if (errorCode(error) !== undefined) for (const item of slice) item.done(false);
          else for (const item of slice) item.fail(error);
        }
      }
  };
  const inProcessClient = (): IamClient<T> => {
    const fetcher = async (url: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
      const iam = await resolveIam();
      const origin = iam.endpoint?.origin ?? binding.url.origin;
      const mount = options.basePath ?? iam.endpoint?.basePath ?? '/api/iam';
      const target = new URL(url instanceof Request ? url.url : url);
      const outgoing = new Headers(init.headers);
      const incoming = headers();
      for (const name of [...forwardedHeaders, 'cookie']) {
        const value = incoming.get(name);
        if (value !== null && !outgoing.has(name)) outgoing.set(name, value);
      }
      outgoing.set('origin', origin);
      // With organization addresses (`hosts`), the call keeps the host the visitor is on, so the server pins it to
      // that organization (and fills in its tenant ID) exactly as it would a browser call from the page.
      const address = iam.hosts ? `${new URL(origin).protocol}//${binding.url.host}` : origin;
      const response = await iam.handler(
        new Request(
          new URL(`${mount}${target.pathname.slice('/api/iam'.length)}${target.search}`, address),
          {
            method: init.method ?? 'POST',
            headers: outgoing,
            ...(init.body === undefined || init.body === null ? {} : { body: init.body }),
          },
        ),
      );
      const issued = response.headers.getSetCookie();
      for (const header of issued) setCookie(header);
      if (issued.length) forget();
      return response;
    };
    return createIamClient<T>({
      baseURL: 'http://better-iam.internal',
      fetch: fetcher as typeof fetch,
    });
  };
  let client: IamClient<T> | undefined;
  const helpers: IamRequest<T> = {
    getSession,
    async requireSession(input = {}) {
      const current = await getSession();
      if (!current) throw new IamRequestError('UNAUTHENTICATED', 'A session is required', 401);
      const failure = input.stepUp ? checkStepUp(current, input.stepUp, clock()) : null;
      if (failure)
        throw new IamRequestError(failure.code, failure.message, failure.status, failure.reason);
      return current;
    },
    async require(action, resource, input = {}) {
      const tenantId = await tenantFor(input.tenantId);
      if (!tenantId) throw new IamRequestError('UNAUTHENTICATED', 'A session is required', 401);
      await (
        await resolveIam()
      ).require({
        ...credential(),
        tenantId,
        action,
        resource: resource ?? { type: 'iam', id: tenantId },
      });
    },
    async can(action, resource, input = {}) {
      const tenantId = await tenantFor(input.tenantId);
      if (!tenantId) return false;
      const check = { action, resource: resource ?? { type: 'iam', id: tenantId } };
      const key = JSON.stringify([tenantId, action, check.resource.type, check.resource.id]);
      let answer = answers.get(key);
      if (!answer) {
        answer = new Promise<boolean>((done, failed) => {
          if (!queue.length) setTimeout(() => void flush(), 0);
          queue.push({ tenantId, check, done, fail: failed });
        });
        answers.set(key, answer);
      }
      return answer;
    },
    async authorize(checks, input = {}) {
      const tenantId = await tenantFor(input.tenantId);
      const resolved = checks.map((check) => ({
        action: check.action,
        resource: check.resource ?? { type: 'iam', id: tenantId ?? '' },
      }));
      if (!tenantId)
        return resolved.map((check) => ({ ...check, allowed: false, reason: 'UNAUTHENTICATED' }));
      const iam = await resolveIam();
      const results: AuthorizeResult[] = [];
      for (let start = 0; start < resolved.length; start += 50) {
        const slice = resolved.slice(start, start + 50);
        try {
          const answer = await iam.authorizeMany({ ...credential(), tenantId, checks: slice });
          slice.forEach((check, index) => {
            const result = answer.results[index];
            results.push({
              ...check,
              allowed: result?.allowed ?? false,
              reason: result?.reason ?? 'DENIED',
            });
          });
        } catch (error) {
          const code = errorCode(error);
          if (code === undefined) throw error;
          for (const check of slice) results.push({ ...check, allowed: false, reason: code });
        }
      }
      return results;
    },
    async listAccessible(input) {
      const iam = await resolveIam();
      if (!iam.listAccessible)
        throw new Error('This IAM server does not list accessible resources');
      const tenantId = await tenantFor(input.tenantId);
      if (!tenantId) return { resources: [], total: 0 } as AccessibleOf<T>;
      return (await iam.listAccessible({
        ...credential(),
        ...input,
        tenantId,
      })) as AccessibleOf<T>;
    },
    async plan(input) {
      const iam = await resolveIam();
      if (!iam.planResources) throw new Error('This IAM server does not plan resources');
      const tenantId = await tenantFor(input.tenantId);
      if (!tenantId)
        return {
          tenantId: '',
          action: input.action,
          type: input.type,
          kind: 'never',
          filter: { kind: 'false' },
        } as PlanOf<T>;
      return (await iam.planResources({
        ...credential(),
        tenantId,
        action: input.action,
        type: input.type,
      })) as PlanOf<T>;
    },
    async assertion(input) {
      const iam = await resolveIam();
      if (!iam.api.assertions) throw new Error('This IAM server does not issue assertions');
      return (await iam.api.assertions.issue(credential(), input)) as AssertionOf<T>;
    },
    get client() {
      return (client ??= inProcessClient());
    },
    credential,
    async signOut() {
      const present = parseCookieHeader(headers().get('cookie'));
      try {
        await (
          helpers.client as unknown as { auth: { signOut(): Promise<unknown> } }
        ).auth.signOut();
      } catch (error) {
        if (errorCode(error) === undefined) throw error;
      }
      const iam = await resolveIam();
      const secure = iam.endpoint?.secure ?? binding.url.protocol === 'https:';
      for (const name of sessionCookies)
        if (present.has(name) && overrides.get(name) !== null)
          setCookie(
            `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secure || name.startsWith('__Host-') ? '; Secure' : ''}`,
          );
      forget();
    },
  };
  return helpers;
}

/** Converts a Node `IncomingMessage`-style header record into `Headers`. */
export function nodeHeaders(record: Record<string, string | string[] | undefined>): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(record))
    if (value !== undefined)
      for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  return headers;
}

/** The IAM API's JSON error envelope, used by every adapter for refusals. */
export function errorBody(error: { code: string; message: string }): string {
  return JSON.stringify({ error: { code: error.code, message: error.message } });
}

/** How a guard should answer a refusal: a redirect for page navigations when a page is configured, else JSON. */
export function refusalResponse(
  error: Error & { code: string; status: number; reason?: string | undefined },
  request: { url: URL; headers: Headers; method: string },
  pages: { loginPath?: string | undefined; stepUpPath?: string | undefined },
): { redirect: string } | { status: number; body: string } {
  const navigation =
    (request.method === 'GET' || request.method === 'HEAD') &&
    (request.headers.get('accept') ?? '').includes('text/html');
  if (navigation) {
    const next = safeRedirectPath(`${request.url.pathname}${request.url.search}`);
    if (error.status === 401 && pages.loginPath)
      return { redirect: withQuery(pages.loginPath, { next }) };
    if (error.reason && pages.stepUpPath)
      return { redirect: withQuery(pages.stepUpPath, { next, reason: error.reason }) };
  }
  return { status: error.status, body: errorBody(error) };
}

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);
/**
 * The CSRF boundary for application routes: a state-changing request authenticated by the session cookie (no
 * `Authorization` header) must come from this application's origin, the IAM origin, or a trusted origin. Session
 * cookies are `SameSite=Lax`, which still sends them from sibling subdomains, so the Origin check matters.
 * Returns the refusal, or null when the request may proceed.
 */
export function checkRequestOrigin(
  request: { method: string; url: URL; headers: Headers },
  trustedOrigins: Iterable<string | undefined> = [],
): IamRequestError | null {
  const { headers } = request;
  if (safeMethods.has(request.method.toUpperCase()) || headers.has('authorization')) return null;
  const cookies = parseCookieHeader(headers.get('cookie'));
  if (!sessionCookies.some((name) => cookies.has(name))) return null;
  if (headers.get('sec-fetch-site') === 'same-origin') return null;
  const origin = headers.get('origin');
  if (!origin) return new IamRequestError('CSRF_REJECTED', 'Cookie requests require Origin', 403);
  // `null` is what sandboxed frames, redirects and no-referrer posts send, and also the `.origin` of non-http trusted
  // entries such as `capacitor://localhost`, so it must never match anything.
  if (origin === 'null')
    return new IamRequestError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
  const forwardedHost = headers.get('x-forwarded-host')?.split(',')[0]?.trim();
  const forwardedProto = headers.get('x-forwarded-proto')?.split(',')[0]?.trim();
  const own = [
    request.url.origin,
    forwardedHost
      ? `${forwardedProto ?? request.url.protocol.slice(0, -1)}://${forwardedHost}`
      : '',
  ];
  const allowed = [...own, ...trustedOrigins].some((entry) => {
    if (!entry) return false;
    try {
      return new URL(entry).origin === origin;
    } catch {
      return false;
    }
  });
  return allowed ? null : new IamRequestError('UNTRUSTED_ORIGIN', 'Origin is not trusted', 403);
}

/** What a guard checks: a session, then optional step-up, then an optional authorization. */
export interface GuardSpec<Req, Session> {
  stepUp?: StepUpRequirement;
  authorize?: {
    action: string;
    /** Defaults to the tenant itself (`iam/{tenantId}`). */
    resource?: (request: Req, session: Session) => MaybePromise<ResourceRef>;
    /** Defaults to the session's tenant. */
    tenantId?: (request: Req, session: Session) => MaybePromise<string>;
  };
}
/** Options every framework adapter shares for its guards. */
export interface GuardOptions {
  /** Origins besides the request's own and the IAM origin that may send cookie-authenticated unsafe requests. */
  trustedOrigins?: string[];
  /** Check `Origin` on cookie-authenticated POST/PUT/PATCH/DELETE requests in guards (default true). */
  csrf?: boolean;
}
/**
 * Runs a guard; resolves with the session or throws the refusal (`IamRequestError` or the server's `IamError`).
 * With `origin`, a cookie-authenticated unsafe request from an untrusted origin is refused first.
 */
export async function enforceGuard<T extends IamLike, Req, Session>(
  helpers: IamRequest<T>,
  request: Req,
  spec: GuardSpec<Req, Session> = {},
  origin?: {
    method: string;
    url: URL;
    headers: Headers;
    trustedOrigins: Iterable<string | undefined>;
  },
): Promise<Session> {
  if (origin) {
    const refusal = checkRequestOrigin(origin, origin.trustedOrigins);
    if (refusal) throw refusal;
  }
  const session = (await helpers.requireSession(
    spec.stepUp ? { stepUp: spec.stepUp } : {},
  )) as Session;
  const rule = spec.authorize;
  if (rule) {
    const tenantId = rule.tenantId ? await rule.tenantId(request, session) : tenantOf(session);
    if (!tenantId) throw new IamRequestError('INVALID_INPUT', 'No tenant to authorize in', 400);
    await helpers.require(
      rule.action,
      rule.resource ? await rule.resource(request, session) : { type: 'iam', id: tenantId },
      { tenantId },
    );
  }
  return session;
}

export type { MaybePromise };
