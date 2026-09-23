import { error as kitError, fail, isHttpError, isRedirect, redirect } from '@sveltejs/kit';
import {
  checkStepUp,
  createRequestHelpers,
  errorCode,
  errorStatus,
  safeRedirectPath,
  tenantOf,
  underPath,
  withQuery,
  type IamLike,
  type IamRequest,
  type ResourceRef,
  type SessionOf,
  type StepUpFailure,
  type StepUpRequirement as CoreStepUpRequirement,
} from '@better-iam/middleware';

export { checkStepUp, isAuthenticationError, safeRedirectPath } from '@better-iam/middleware';
export type {
  AccessibleOf,
  AssertionInput,
  AssertionOf,
  AuthorizeCheck,
  AuthorizeResult,
  IamLike,
  ResourceRef,
  SessionOf,
  StepUpFailure,
} from '@better-iam/middleware';
type MaybePromise<T> = T | Promise<T>;

/** The cookie jar SvelteKit passes on every request event (`event.cookies`). */
export interface KitCookies {
  get(name: string): string | undefined;
  getAll(): { name: string; value: string }[];
  set(name: string, value: string, options: KitCookieOptions): void;
}
export interface KitCookieOptions {
  path: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  domain?: string;
  maxAge?: number;
  expires?: Date;
}
/** The parts of a SvelteKit `RequestEvent` (hooks, server loads, actions, `+server.ts`) these helpers read. */
export interface KitEvent {
  request: Request;
  url: URL;
  cookies: KitCookies;
  locals: object;
  isDataRequest?: boolean;
}

/**
 * Extra assurance a session must show. `mfa: true` needs a session that completed MFA; `'fresh'` also refuses
 * remembered devices, impersonation, assumed roles, and API keys. `maxAgeMs` needs a recent sign-in.
 */
export interface StepUpRequirement extends CoreStepUpRequirement {
  /** Where pages send people to step up; defaults to the `stepUpPath` option, else the failure is a 403. */
  redirectTo?: string;
}

/** A path rule enforced by `handle` before any load, action, or endpoint of the matching routes runs. */
export interface ProtectRule<Session> {
  /** A path prefix matched on segment boundaries (`/admin` covers `/admin/users`), a pattern, or a predicate. */
  path: string | RegExp | ((url: URL) => boolean);
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ event: KitEvent; session: Session }>;
  /** Where a denied visitor goes; without it the denial is a 403 error page. */
  deniedRedirect?: string;
}
export interface AuthorizeSpec<Input> {
  action: string;
  /** Defaults to the tenant itself (`iam/{tenantId}`). */
  resource?: (input: Input) => MaybePromise<ResourceRef>;
  /** Defaults to the session's tenant. */
  tenantId?: (input: Input) => MaybePromise<string>;
}
export interface GuardSpec<Event, Session> {
  /** Where signed-out visitors go instead of the `loginPath` option. */
  loginRedirect?: string;
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ event: Event; session: Session }>;
  /** Where a denied visitor goes; without it the denial is a 403 error. */
  deniedRedirect?: string;
}
export interface ActionSpec<Event, Session> {
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<{ event: Event; session: Session }>;
}
/** What a guarded form action returns for an IAM refusal: `fail(status, { code, message })`. */
export interface IamActionFailure {
  code: string;
  message: string;
}

export interface IamKitOptions {
  /** Where the IAM HTTP API is served; defaults to the instance's `endpoint.basePath`, else `/api/iam`. */
  basePath?: string;
  /** Serve the IAM HTTP API from `handle` (default true). Turn off when another route mounts `iam.handler`. */
  serveApi?: boolean;
  /** Where signed-out visitors are sent (`?next=` carries the path they wanted). Default `/login`. */
  loginPath?: string;
  /** Where sessions that must step up are sent (`?next=` and `?reason=mfa|recent|impersonation`). */
  stepUpPath?: string;
  /** Rules `handle` enforces before routing. */
  protect?: ProtectRule<unknown>[];
  /** The `event.locals` key the per-request helpers live under (default `iam`). */
  localsKey?: string;
  now?: () => number;
}

/** True for SvelteKit's own control-flow throws (`redirect()`, `error()`), which must propagate untouched. */
export function isKitControlError(error: unknown): boolean {
  return isRedirect(error) || isHttpError(error);
}
function pathMatches(rule: ProtectRule<unknown>['path'], url: URL): boolean {
  if (typeof rule === 'function') return rule(url);
  if (rule instanceof RegExp) return rule.test(url.pathname);
  return underPath(url.pathname, rule);
}

/** Parses one `Set-Cookie` header into the name, decoded value, and options `event.cookies.set` accepts. */
export function parseSetCookie(
  header: string,
): { name: string; value: string; options: KitCookieOptions } | undefined {
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
  const options: KitCookieOptions = { path: '/' };
  for (const attribute of attributes) {
    const [rawKey = '', ...rest] = attribute.split('=');
    const key = rawKey.trim().toLowerCase();
    const setting = rest.join('=').trim();
    if (key === 'httponly') options.httpOnly = true;
    else if (key === 'secure') options.secure = true;
    else if (key === 'path' && setting) options.path = setting;
    else if (key === 'domain' && setting) options.domain = setting;
    else if (key === 'max-age' && /^-?\d+$/.test(setting)) options.maxAge = Number(setting);
    else if (key === 'expires' && !Number.isNaN(Date.parse(setting)))
      options.expires = new Date(setting);
    else if (key === 'samesite') {
      const mode = setting.toLowerCase();
      if (mode === 'lax' || mode === 'strict' || mode === 'none') options.sameSite = mode;
    }
  }
  // SvelteKit defaults `secure` to true outside localhost; the IAM server decides, so say it explicitly.
  options.secure ??= false;
  options.httpOnly ??= false;
  return { name, value, options };
}

/**
 * The per-request helpers `handle` puts on `event.locals.iam` (or `kit.locals(event)` builds on demand): the shared
 * `@better-iam/middleware` helpers, with `requireSession` and `require` answering the SvelteKit way (login / step-up
 * redirects, `error(403, { code })`). Cookies the in-process client receives are written to `event.cookies`, and later
 * calls in the same request see them.
 */
export interface IamLocals<T extends IamLike>
  extends Omit<IamRequest<T>, 'requireSession' | 'require'> {
  /** The current session, or a redirect to the login page (`?next=` = this path) / the step-up page. */
  requireSession(options?: {
    stepUp?: StepUpRequirement;
    loginRedirect?: string;
    returnTo?: string;
  }): Promise<SessionOf<T>>;
  /**
   * Enforces one action (default resource: the tenant). Signed-out visitors are redirected to the login page;
   * denials redirect to `deniedRedirect` when given and otherwise throw a 403 `error()` carrying the IAM `code`.
   */
  require(
    action: string,
    resource?: ResourceRef,
    options?: { tenantId?: string; deniedRedirect?: string },
  ): Promise<void>;
}

const localsState = new WeakMap<object, unknown>();

/**
 * SvelteKit integration: `handle` serves the IAM HTTP API, enforces `protect` rules, and gives every request
 * `event.locals.iam`; `guard` and `action` wrap server loads and form actions.
 *
 * ```ts
 * // src/hooks.server.ts
 * export const iamKit = createIamKit(iam, { protect: [{ path: '/app' }] });
 * export const handle = iamKit.handle;
 * ```
 */
export function createIamKit<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamKitOptions = {},
) {
  type Session = SessionOf<T>;
  const resolveIam = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const loginPath = options.loginPath ?? '/login';
  const localsKey = options.localsKey ?? 'iam';
  const clock = options.now ?? Date.now;
  const basePath = async (): Promise<string> =>
    options.basePath ?? (await resolveIam()).endpoint?.basePath ?? '/api/iam';

  function build(event: KitEvent): IamLocals<T> {
    const core = createRequestHelpers(
      resolveIam,
      {
        url: event.url,
        // The jar, not the raw header: cookies set earlier in this request (by the app or a sign-in) count.
        get headers() {
          const headers = new Headers(event.request.headers);
          const jar = event.cookies
            .getAll()
            .map(({ name, value }) => `${name}=${encodeURIComponent(value)}`)
            .join('; ');
          if (jar) headers.set('cookie', jar);
          else headers.delete('cookie');
          return headers;
        },
        setCookie: (header) => {
          const cookie = parseSetCookie(header);
          if (cookie) event.cookies.set(cookie.name, cookie.value, cookie.options);
        },
      },
      { ...(options.basePath ? { basePath: options.basePath } : {}), now: clock },
    );
    const returnPath = () => safeRedirectPath(`${event.url.pathname}${event.url.search}`);
    const toLogin = (target: string | undefined, returnTo: string | undefined): never =>
      redirect(303, withQuery(target ?? loginPath, { next: returnTo ?? returnPath() }));
    const stepUpOrFail = (failure: StepUpFailure, requirement: StepUpRequirement): never => {
      const target = requirement.redirectTo ?? options.stepUpPath;
      if (target === undefined)
        kitError(failure.status, { message: failure.message, code: failure.code } as never);
      redirect(303, withQuery(target, { next: returnPath(), reason: failure.reason }));
    };
    return {
      getSession: core.getSession,
      can: core.can,
      authorize: core.authorize,
      listAccessible: core.listAccessible,
      assertion: core.assertion,
      get client() {
        return core.client;
      },
      credential: core.credential,
      signOut: core.signOut,
      async requireSession(input = {}) {
        const current = await core.getSession();
        if (!current) return toLogin(input.loginRedirect, input.returnTo);
        const failure = input.stepUp ? checkStepUp(current, input.stepUp, clock()) : null;
        if (failure) return stepUpOrFail(failure, input.stepUp!);
        return current;
      },
      async require(action, resource, input = {}) {
        try {
          await core.require(
            action,
            resource,
            input.tenantId === undefined ? {} : { tenantId: input.tenantId },
          );
        } catch (error) {
          const code = errorCode(error);
          if (code === undefined) throw error;
          if (code === 'UNAUTHENTICATED') return toLogin(undefined, undefined);
          if (input.deniedRedirect && code === 'ACCESS_DENIED') redirect(303, input.deniedRedirect);
          kitError(errorStatus(error) ?? 403, {
            message: error instanceof Error ? error.message : code,
            code,
          } as never);
        }
      },
    };
  }

  const locals = (event: KitEvent): IamLocals<T> => {
    const bag = event.locals as Record<string, unknown>;
    const existing = localsState.get(event.locals) as IamLocals<T> | undefined;
    if (existing) return existing;
    const created = build(event);
    localsState.set(event.locals, created);
    if (!(localsKey in bag)) bag[localsKey] = created;
    return created;
  };

  const authorizeFor = async <Input extends { session: unknown }>(
    helpers: IamLocals<T>,
    spec: AuthorizeSpec<Input> | undefined,
    input: Input,
    deniedRedirect: string | undefined,
  ): Promise<void> => {
    if (!spec) return;
    const tenantId = spec.tenantId ? await spec.tenantId(input) : tenantOf(input.session);
    if (!tenantId)
      kitError(400, { message: 'No tenant to authorize in', code: 'INVALID_INPUT' } as never);
    await helpers.require(
      spec.action,
      spec.resource ? await spec.resource(input) : { type: 'iam', id: tenantId },
      { tenantId, ...(deniedRedirect ? { deniedRedirect } : {}) },
    );
  };

  return {
    /** Resolves the IAM instance (the `source` may be a lazy factory). */
    resolve: resolveIam,
    /** The per-request helpers for any request event; `handle` also stores them on `event.locals.iam`. */
    locals,
    /**
     * The `handle` hook: serves the IAM API under `basePath`, attaches `event.locals.iam`, and enforces `protect`
     * rules (signed-out → login redirect with `?next=`, step-up → `stepUpPath`, denied → `deniedRedirect` or 403).
     * Compose with other hooks through SvelteKit's `sequence`.
     */
    async handle<E extends KitEvent>(input: {
      event: E;
      resolve(event: E): MaybePromise<Response>;
    }): Promise<Response> {
      const { event } = input;
      if (options.serveApi !== false && underPath(event.url.pathname, await basePath()))
        return (await resolveIam()).handler(event.request);
      const helpers = locals(event);
      for (const rule of options.protect ?? []) {
        if (!pathMatches(rule.path, event.url)) continue;
        const session = await helpers.requireSession(rule.stepUp ? { stepUp: rule.stepUp } : {});
        await authorizeFor(helpers, rule.authorize, { event, session }, rule.deniedRedirect);
      }
      return input.resolve(event);
    },
    /**
     * Wraps a server `load` (or a `+server.ts` handler taking the event): the wrapped function receives the session
     * as its second argument and runs only when the visitor is signed in, stepped up, and allowed.
     *
     * `export const load = iamKit.guard(async (event, session) => ({ name: session.identity.name }), { stepUp: { mfa: true } })`
     */
    guard<E extends KitEvent, R>(
      load: (event: E, session: Session) => R,
      spec: GuardSpec<E, Session> = {},
    ): (event: E) => Promise<Awaited<R>> {
      return async (event: E): Promise<Awaited<R>> => {
        const helpers = locals(event);
        const session = await helpers.requireSession({
          ...(spec.stepUp ? { stepUp: spec.stepUp } : {}),
          ...(spec.loginRedirect ? { loginRedirect: spec.loginRedirect } : {}),
        });
        await authorizeFor(helpers, spec.authorize, { event, session }, spec.deniedRedirect);
        return (await load(event, session)) as Awaited<R>;
      };
    },
    /**
     * Wraps a form action. IAM refusals (signed out, step-up, denied, validation, rate limits) come back as
     * `fail(status, { code, message })` for `form` to show; redirects and other errors propagate.
     */
    action<E extends KitEvent, R>(
      fn: (event: E, session: Session) => R,
      spec: ActionSpec<E, Session> = {},
    ) {
      return async (event: E) => {
        const helpers = locals(event);
        try {
          const session = await helpers.getSession();
          if (!session)
            return fail(401, {
              code: 'UNAUTHENTICATED',
              message: 'Sign in to continue',
            } satisfies IamActionFailure);
          const failure = spec.stepUp ? checkStepUp(session, spec.stepUp, clock()) : null;
          if (failure)
            return fail(failure.status, {
              code: failure.code,
              message: failure.message,
            } satisfies IamActionFailure);
          if (spec.authorize) {
            const input = { event, session };
            const tenantId = spec.authorize.tenantId
              ? await spec.authorize.tenantId(input)
              : tenantOf(session);
            if (!tenantId)
              return fail(400, {
                code: 'INVALID_INPUT',
                message: 'No tenant to authorize in',
              } satisfies IamActionFailure);
            await (
              await resolveIam()
            ).require({
              ...helpers.credential(),
              tenantId,
              action: spec.authorize.action,
              resource: spec.authorize.resource
                ? await spec.authorize.resource(input)
                : { type: 'iam', id: tenantId },
            });
          }
          return await fn(event, session);
        } catch (error) {
          if (isKitControlError(error)) throw error;
          const code = errorCode(error);
          const status = errorStatus(error);
          if (code === undefined || status === undefined || status < 400 || status >= 500)
            throw error;
          return fail(status, {
            code,
            message: error instanceof Error ? error.message : code,
          } satisfies IamActionFailure);
        }
      };
    },
    /**
     * For the root `+layout.server.ts`: `{ session }` to hand to `createIam({ initialSession: data.session })`, so the
     * first render already knows who is signed in.
     */
    async sessionData(event: KitEvent): Promise<{ session: Session | null }> {
      return { session: await locals(event).getSession() };
    },
  };
}
export type IamKit<T extends IamLike = IamLike> = ReturnType<typeof createIamKit<T>>;
