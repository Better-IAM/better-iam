import {
  createRequestHelpers,
  enforceGuard,
  isIamRefusal,
  refusalResponse,
  underPath,
  type GuardOptions,
  type GuardSpec,
  type IamLike,
  type IamRequest,
  type RequestHelperOptions,
  type SessionOf,
} from './index.js';

/** The parts of a Hono `Context` the middleware uses (Hono 4). */
export interface HonoContext {
  req: { raw: Request; url: string; method: string };
  header(name: string, value: string, options?: { append?: boolean }): void;
  set(key: string, value: unknown): void;
  get(key: string): unknown;
}
export type HonoNext = () => Promise<void>;
export type HonoMiddleware = (context: never, next: HonoNext) => Promise<Response | void>;

/** Declare on your app for typed access: `new Hono<{ Variables: IamVariables<typeof iam> }>()`, then `c.get('iam')`. */
export interface IamVariables<T extends IamLike> {
  iam: IamRequest<T>;
}

export interface IamHonoOptions extends RequestHelperOptions, GuardOptions {
  /** Path prefixes the IAM server answers (default: its `basePath`). */
  serve?: string[];
  /** Where page navigations (GET with `Accept: text/html`) go when signed out; `?next=` carries the path. */
  loginPath?: string;
  /** Where page navigations go when the session must step up (`?next=`, `?reason=`). */
  stepUpPath?: string;
}

/**
 * Hono integration (Node, Bun, Deno, Workers). `middleware` answers the IAM API with `iam.handler` and sets
 * `c.get('iam')` for every other request; `requireSession` and `authorize` are route guards; `onError` turns IAM
 * refusals thrown by handlers into the JSON error envelope. Node-only protocol mounts (the OAuth provider) need the
 * Node adapters instead.
 *
 * ```ts
 * const iamHono = createIamHono(iam);
 * const app = new Hono<{ Variables: IamVariables<typeof iam> }>();
 * app.use(iamHono.middleware);
 * app.get('/me', iamHono.requireSession(), async (c) => c.json((await c.get('iam').getSession())!.identity));
 * app.onError(iamHono.onError);
 * ```
 */
export function createIamHono<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamHonoOptions = {},
) {
  type Session = SessionOf<T>;
  const resolveIam = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const helpersFor = (c: HonoContext): IamRequest<T> => {
    const existing = c.get('iam') as IamRequest<T> | undefined;
    if (existing) return existing;
    const created = createRequestHelpers(
      resolveIam,
      {
        url: new URL(c.req.url),
        headers: c.req.raw.headers,
        setCookie: (header) => c.header('set-cookie', header, { append: true }),
      },
      options,
    );
    c.set('iam', created);
    return created;
  };
  const refusal = (c: HonoContext, error: Error & { code: string; status: number }): Response => {
    const answer = refusalResponse(
      error,
      { url: new URL(c.req.url), headers: c.req.raw.headers, method: c.req.method },
      { loginPath: options.loginPath, stepUpPath: options.stepUpPath },
    );
    if ('redirect' in answer)
      return new Response(null, { status: 303, headers: { location: answer.redirect } });
    return new Response(answer.body, {
      status: answer.status,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  };
  const guard =
    (spec: GuardSpec<HonoContext, Session>) =>
    async (c: HonoContext, next: HonoNext): Promise<Response | void> => {
      try {
        const iam = await resolveIam();
        await enforceGuard(
          helpersFor(c),
          c,
          spec,
          options.csrf === false
            ? undefined
            : {
                method: c.req.method,
                url: new URL(c.req.url),
                headers: c.req.raw.headers,
                trustedOrigins: [iam.endpoint?.origin, ...(options.trustedOrigins ?? [])],
              },
        );
      } catch (error) {
        if (isIamRefusal(error)) return refusal(c, error);
        throw error;
      }
      await next();
    };
  return {
    resolve: resolveIam,
    /** The per-request helpers (`c.get('iam')`), created on first use. */
    helpers: helpersFor,
    /** Answers the IAM API under `serve` prefixes and sets `c.get('iam')` for everything else. */
    middleware: async (c: HonoContext, next: HonoNext): Promise<Response | void> => {
      const iam = await resolveIam();
      const prefixes = options.serve ?? [options.basePath ?? iam.endpoint?.basePath ?? '/api/iam'];
      if (prefixes.some((prefix) => underPath(new URL(c.req.url).pathname, prefix)))
        return iam.handler(c.req.raw);
      helpersFor(c);
      await next();
    },
    /** Requires a session (and `stepUp`, when given). */
    requireSession: (spec: Pick<GuardSpec<HonoContext, Session>, 'stepUp'> = {}) => guard(spec),
    /** Requires a session allowed to perform `action` (default resource: the tenant). */
    authorize: (
      action: string,
      spec: Omit<NonNullable<GuardSpec<HonoContext, Session>['authorize']>, 'action'> &
        Pick<GuardSpec<HonoContext, Session>, 'stepUp'> = {},
    ) => {
      const { stepUp, ...rule } = spec;
      return guard({ ...(stepUp ? { stepUp } : {}), authorize: { action, ...rule } });
    },
    /**
     * `app.onError(iamHono.onError)`: IAM refusals become the JSON envelope; `HTTPException`s answer with their own
     * response; anything else is logged and answered with a plain 500, as Hono's default handler does.
     */
    onError: (error: Error, c: HonoContext): Response => {
      if (isIamRefusal(error)) return refusal(c, error);
      const own = (error as { getResponse?: unknown }).getResponse;
      if (typeof own === 'function') return own.call(error) as Response;
      console.error(error);
      return new Response('Internal Server Error', { status: 500 });
    },
  };
}
export type IamHono<T extends IamLike = IamLike> = ReturnType<typeof createIamHono<T>>;
export type { IamRequest } from './index.js';
