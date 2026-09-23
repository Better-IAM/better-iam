import { createContext, data, redirect, type RouterContextProvider } from 'react-router';
import {
  checkRequestOrigin,
  checkStepUp,
  createRequestHelpers,
  errorCode,
  errorStatus,
  safeRedirectPath,
  tenantOf,
  withQuery,
  type GuardOptions,
  type IamLike,
  type IamRequest,
  type RequestHelperOptions,
  type ResourceRef,
  type SessionOf,
  type StepUpFailure,
  type StepUpRequirement as CoreStepUpRequirement,
} from '@better-iam/middleware';

export {
  checkRequestOrigin,
  checkStepUp,
  isAuthenticationError,
  safeRedirectPath,
} from '@better-iam/middleware';
export type {
  AuthorizeResult,
  IamLike,
  IamRequest,
  ResourceRef,
  SessionOf,
  StepUpFailure,
} from '@better-iam/middleware';
type MaybePromise<T> = T | Promise<T>;

/** The loader / action / middleware arguments these helpers read. */
export interface RouteArgs {
  request: Request;
  context: Readonly<RouterContextProvider>;
}

export interface StepUpRequirement extends CoreStepUpRequirement {
  /** Where to send people to step up; defaults to the `stepUpPath` option, else the failure is a 403. */
  redirectTo?: string;
}
export interface AuthorizeSpec<Args, Session> {
  action: string;
  /** Defaults to the tenant itself (`iam/{tenantId}`). */
  resource?: (args: Args, session: Session) => MaybePromise<ResourceRef>;
  /** Defaults to the session's tenant. */
  tenantId?: (args: Args, session: Session) => MaybePromise<string>;
}
export interface GuardSpec<Args, Session> {
  /** Where signed-out visitors go instead of the `loginPath` option. */
  loginRedirect?: string;
  stepUp?: StepUpRequirement;
  authorize?: AuthorizeSpec<Args, Session>;
  /** Where a denied visitor goes; without it the denial is thrown as `data({ code, message }, 403)`. */
  deniedRedirect?: string;
}
export interface ActionSpec<Args, Session> {
  stepUp?: CoreStepUpRequirement;
  authorize?: AuthorizeSpec<Args, Session>;
}
/** What a guarded action returns for an IAM refusal, with the refusal's HTTP status. */
export interface IamActionFailure {
  code: string;
  message: string;
}

export interface IamRouterOptions extends RequestHelperOptions, GuardOptions {
  /** Where signed-out visitors are sent (`?next=` carries the path they wanted). Default `/login`. */
  loginPath?: string;
  /** Where sessions that must step up are sent (`?next=` and `?reason=mfa|recent|impersonation`). */
  stepUpPath?: string;
}

/** Appends `Set-Cookie` headers to a response, copying it when its headers are immutable (`Response.redirect`). */
function withCookies(response: Response, cookies: string[]): Response {
  if (!cookies.length) return response;
  try {
    for (const cookie of cookies) response.headers.append('set-cookie', cookie);
    return response;
  } catch {
    const headers = new Headers(response.headers);
    for (const cookie of cookies) headers.append('set-cookie', cookie);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }
}

/**
 * React Router (framework mode, v7.9+ / v8) integration. `middleware` goes on the root route and gives every loader and
 * action `iamRouter.helpers(args)`; cookies the in-process client receives are added to the response. `api` is the
 * loader and action of an `api/iam/*` resource route. `guard` / `action` wrap loaders and actions.
 *
 * ```ts
 * // app/iam.server.ts
 * export const iamRouter = createIamRouter(iam, { loginPath: '/login' });
 * // app/root.tsx
 * export const middleware = [iamRouter.middleware];
 * // app/routes/api.iam.$.ts
 * export const loader = iamRouter.api;
 * export const action = iamRouter.api;
 * ```
 */
export function createIamRouter<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamRouterOptions = {},
) {
  type Session = SessionOf<T>;
  const resolveIam = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const loginPath = options.loginPath ?? '/login';
  const clock = options.now ?? Date.now;
  const iamContext = createContext<IamRequest<T> | null>(null);

  const helpers = (args: RouteArgs): IamRequest<T> => {
    const found = args.context.get(iamContext);
    if (!found)
      throw new Error(
        'Better IAM helpers need `export const middleware = [iamRouter.middleware]` on the root route',
      );
    return found;
  };
  const returnPath = (request: Request) => {
    const url = new URL(request.url);
    return safeRedirectPath(`${url.pathname.replace(/\.data$/, '')}${url.search}`);
  };
  const toLogin = (request: Request, target?: string, returnTo?: string): never => {
    throw redirect(withQuery(target ?? loginPath, { next: returnTo ?? returnPath(request) }));
  };
  const refuse = (code: string, message: string, status: number): never => {
    throw data({ code, message } satisfies IamActionFailure, { status });
  };
  const stepUpOrRefuse = (
    request: Request,
    failure: StepUpFailure,
    requirement: StepUpRequirement,
  ): never => {
    const target = requirement.redirectTo ?? options.stepUpPath;
    if (target === undefined) return refuse(failure.code, failure.message, failure.status);
    throw redirect(withQuery(target, { next: returnPath(request), reason: failure.reason }));
  };
  const trusted = async () => [
    (await resolveIam()).endpoint?.origin,
    ...(options.trustedOrigins ?? []),
  ];
  const originRefusal = async (request: Request) =>
    options.csrf === false
      ? null
      : checkRequestOrigin(
          { method: request.method, url: new URL(request.url), headers: request.headers },
          await trusted(),
        );

  const requireSession = async (
    args: RouteArgs,
    input: { stepUp?: StepUpRequirement; loginRedirect?: string; returnTo?: string } = {},
  ): Promise<Session> => {
    const session = await helpers(args).getSession();
    if (!session) return toLogin(args.request, input.loginRedirect, input.returnTo);
    const failure = input.stepUp ? checkStepUp(session, input.stepUp, clock()) : null;
    if (failure) return stepUpOrRefuse(args.request, failure, input.stepUp!);
    return session;
  };
  const requireAction = async (
    args: RouteArgs,
    action: string,
    resource?: ResourceRef,
    input: { tenantId?: string; deniedRedirect?: string } = {},
  ): Promise<void> => {
    try {
      await helpers(args).require(
        action,
        resource,
        input.tenantId === undefined ? {} : { tenantId: input.tenantId },
      );
    } catch (error) {
      const code = errorCode(error);
      if (code === undefined) throw error;
      if (code === 'UNAUTHENTICATED') return toLogin(args.request);
      if (input.deniedRedirect && code === 'ACCESS_DENIED') throw redirect(input.deniedRedirect);
      return refuse(code, error instanceof Error ? error.message : code, errorStatus(error) ?? 403);
    }
  };

  return {
    /** Resolves the IAM instance (the `source` may be a lazy factory). */
    resolve: resolveIam,
    /** The router context key holding the per-request helpers. */
    context: iamContext,
    /** Root-route middleware: per-request helpers in the router context, IAM cookies on the response. */
    middleware: async (
      args: { request: Request; context: Readonly<RouterContextProvider> },
      next: () => Promise<Response>,
    ): Promise<Response> => {
      const cookies: string[] = [];
      args.context.set(
        iamContext,
        createRequestHelpers(
          resolveIam,
          {
            url: new URL(args.request.url),
            headers: args.request.headers,
            setCookie: (header) => cookies.push(header),
          },
          options,
        ),
      );
      return withCookies(await next(), cookies);
    },
    /** Loader and action for an `api/iam/*` resource route: the IAM HTTP API. */
    api: async ({ request }: { request: Request }): Promise<Response> =>
      (await resolveIam()).handler(request),
    /** The per-request helpers (session, decisions, in-process client, sign-out). */
    helpers,
    /** The session, or a redirect to the login page (`?next=` = this path) / the step-up page. */
    requireSession,
    /**
     * Enforces one action (default resource: the tenant). Signed out → login redirect; denied → `deniedRedirect`, or a
     * thrown `data({ code, message }, { status: 403 })` for the route's error boundary.
     */
    require: requireAction,
    /**
     * Wraps a loader: runs it with the session as the second argument once the visitor is signed in, stepped up, and
     * allowed. `export const loader = iamRouter.guard(async (args, session) => ({ name: session.identity.name }))`
     */
    guard<A extends RouteArgs, R>(
      loader: (args: A, session: Session) => R,
      spec: GuardSpec<A, Session> = {},
    ): (args: A) => Promise<Awaited<R>> {
      return async (args: A): Promise<Awaited<R>> => {
        const refusal = await originRefusal(args.request);
        if (refusal) return refuse(refusal.code, refusal.message, refusal.status);
        const session = await requireSession(args, {
          ...(spec.stepUp ? { stepUp: spec.stepUp } : {}),
          ...(spec.loginRedirect ? { loginRedirect: spec.loginRedirect } : {}),
        });
        const rule = spec.authorize;
        if (rule) {
          const tenantId = rule.tenantId ? await rule.tenantId(args, session) : tenantOf(session);
          if (!tenantId) return refuse('INVALID_INPUT', 'No tenant to authorize in', 400);
          await requireAction(
            args,
            rule.action,
            rule.resource ? await rule.resource(args, session) : { type: 'iam', id: tenantId },
            { tenantId, ...(spec.deniedRedirect ? { deniedRedirect: spec.deniedRedirect } : {}) },
          );
        }
        return (await loader(args, session)) as Awaited<R>;
      };
    },
    /**
     * Wraps an action. Cross-origin cookie requests are refused first; IAM refusals (signed out, step-up, denied,
     * invalid input, rate limits) come back as `data({ code, message }, { status })` for `useActionData`; redirects
     * and other errors propagate.
     */
    action<A extends RouteArgs, R>(
      fn: (args: A, session: Session) => R,
      spec: ActionSpec<A, Session> = {},
    ) {
      const failure = (code: string, message: string, status: number) =>
        data({ code, message } satisfies IamActionFailure, { status });
      return async (args: A) => {
        const refusal = await originRefusal(args.request);
        if (refusal) return failure(refusal.code, refusal.message, refusal.status);
        try {
          const session = await helpers(args).getSession();
          if (!session) return failure('UNAUTHENTICATED', 'Sign in to continue', 401);
          const stepUp = spec.stepUp ? checkStepUp(session, spec.stepUp, clock()) : null;
          if (stepUp) return failure(stepUp.code, stepUp.message, stepUp.status);
          const rule = spec.authorize;
          if (rule) {
            const tenantId = rule.tenantId ? await rule.tenantId(args, session) : tenantOf(session);
            if (!tenantId) return failure('INVALID_INPUT', 'No tenant to authorize in', 400);
            await helpers(args).require(
              rule.action,
              rule.resource ? await rule.resource(args, session) : { type: 'iam', id: tenantId },
              { tenantId },
            );
          }
          return await fn(args, session);
        } catch (error) {
          if (error instanceof Response) throw error;
          const code = errorCode(error);
          const status = errorStatus(error);
          if (code === undefined || status === undefined || status < 400 || status >= 500)
            throw error;
          return failure(code, error instanceof Error ? error.message : code, status);
        }
      };
    },
    /** For the root loader: `{ session }` for `<IamProvider initialSession={...}>`. */
    async sessionData(args: RouteArgs): Promise<{ session: Session | null }> {
      return { session: await helpers(args).getSession() };
    },
  };
}
export type IamRouter<T extends IamLike = IamLike> = ReturnType<typeof createIamRouter<T>>;
