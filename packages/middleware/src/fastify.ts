import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  createRequestHelpers,
  enforceGuard,
  isIamRefusal,
  nodeHeaders,
  refusalResponse,
  underPath,
  type GuardOptions,
  type GuardSpec,
  type IamLike,
  type IamRequest,
  type RequestHelperOptions,
  type SessionOf,
} from './index.js';

/** The largest request body the fallback path buffers for the IAM handler (as the Express adapter). */
const maxBody = 2097152;

/** The Fastify (4 or 5) request fields the plugin reads. */
export interface FastifyRequestLike {
  raw: IncomingMessage;
  url: string;
  method: string;
  protocol?: string;
  headers: Record<string, string | string[] | undefined>;
  iam?: unknown;
}
/** The Fastify reply methods the plugin uses. */
export interface FastifyReplyLike {
  raw: ServerResponse;
  sent?: boolean;
  hijack(): unknown;
  code(status: number): FastifyReplyLike;
  header(name: string, value: unknown): FastifyReplyLike;
  getHeader(name: string): unknown;
  redirect(url: string, code?: number): unknown;
  send(payload?: unknown): unknown;
}
/** The Fastify instance methods the plugin uses. */
export interface FastifyInstanceLike {
  decorateRequest(name: string, value: unknown): unknown;
  addHook(name: 'onRequest', hook: FastifyHook): unknown;
}
export type FastifyHook = (
  request: FastifyRequestLike,
  reply: FastifyReplyLike,
) => Promise<unknown>;

export interface IamFastifyOptions extends RequestHelperOptions, GuardOptions {
  /**
   * Path prefixes the IAM server answers (default: its `basePath`). Add protocol mounts outside it, e.g. `'/oauth'`,
   * so their requests reach `iam.nodeHandler` too.
   */
  serve?: string[];
  /** Where page navigations (GET with `Accept: text/html`) go when signed out; `?next=` carries the path. */
  loginPath?: string;
  /** Where page navigations go when the session must step up (`?next=`, `?reason=`). */
  stepUpPath?: string;
}

function requestUrl(request: FastifyRequestLike): URL {
  const host = request.headers.host;
  return new URL(
    request.url,
    `${request.protocol ?? 'http'}://${typeof host === 'string' ? host : 'localhost'}`,
  );
}

/**
 * Fastify integration. `plugin` (register it with `app.register(iamFastify.plugin)`) answers the IAM API in an
 * `onRequest` hook, before Fastify parses bodies, through `iam.nodeHandler`; every other request gets `request.iam`.
 * `requireSession` and `authorize` are `preHandler` guards; `errorHandler` answers IAM refusals your routes throw.
 *
 * ```ts
 * const iamFastify = createIamFastify(iam, { loginPath: '/login' });
 * await app.register(iamFastify.plugin);
 * app.get('/admin', { preHandler: iamFastify.authorize('iam:identities:read') }, handler);
 * app.setErrorHandler(iamFastify.errorHandler);
 * ```
 */
export function createIamFastify<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamFastifyOptions = {},
) {
  type Session = SessionOf<T>;
  const resolveIam = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const state = new WeakMap<object, IamRequest<T>>();
  const helpersFor = (request: FastifyRequestLike, reply: FastifyReplyLike): IamRequest<T> => {
    const existing = state.get(request);
    if (existing) return existing;
    const created = createRequestHelpers(
      resolveIam,
      {
        url: requestUrl(request),
        headers: nodeHeaders(request.headers),
        setCookie: (header) => {
          const current = reply.getHeader('set-cookie');
          const list =
            current === undefined ? [] : Array.isArray(current) ? current : [String(current)];
          reply.header('set-cookie', [...list, header]);
        },
      },
      options,
    );
    state.set(request, created);
    request.iam = created;
    return created;
  };
  const answer = (
    request: FastifyRequestLike,
    reply: FastifyReplyLike,
    error: Error & { code: string; status: number },
  ) => {
    const result = refusalResponse(
      error,
      { url: requestUrl(request), headers: nodeHeaders(request.headers), method: request.method },
      { loginPath: options.loginPath, stepUpPath: options.stepUpPath },
    );
    if ('redirect' in result) return reply.redirect(result.redirect, 303);
    return reply
      .code(result.status)
      .header('content-type', 'application/json')
      .header('cache-control', 'no-store')
      .send(result.body);
  };
  const guard =
    (spec: GuardSpec<FastifyRequestLike, Session>) =>
    async (request: FastifyRequestLike, reply: FastifyReplyLike): Promise<unknown> => {
      try {
        const iam = await resolveIam();
        await enforceGuard(
          helpersFor(request, reply),
          request,
          spec,
          options.csrf === false
            ? undefined
            : {
                method: request.method,
                url: requestUrl(request),
                headers: nodeHeaders(request.headers),
                trustedOrigins: [iam.endpoint?.origin, ...(options.trustedOrigins ?? [])],
              },
        );
      } catch (error) {
        if (isIamRefusal(error)) return answer(request, reply, error);
        throw error;
      }
      return undefined;
    };

  // `unknown` so any Fastify instance type fits `app.register`; it is used through FastifyInstanceLike.
  const plugin = async (instance: unknown): Promise<void> => {
    const app = instance as FastifyInstanceLike;
    app.decorateRequest('iam', null);
    app.addHook('onRequest', (async (request: FastifyRequestLike, reply: FastifyReplyLike) => {
      const iam = await resolveIam();
      const prefixes = options.serve ?? [options.basePath ?? iam.endpoint?.basePath ?? '/api/iam'];
      if (!prefixes.some((prefix) => underPath(requestUrl(request).pathname, prefix))) {
        helpersFor(request, reply);
        return;
      }
      reply.hijack();
      if (iam.nodeHandler) {
        await (iam.nodeHandler as (req: IncomingMessage, res: ServerResponse) => Promise<void>)(
          request.raw,
          reply.raw,
        );
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      if (request.method !== 'GET' && request.method !== 'HEAD')
        for await (const chunk of request.raw) {
          const buffer = Buffer.from(chunk as Uint8Array);
          // Bounded like the Express adapter: an unauthenticated caller must not make the process buffer without limit.
          size += buffer.length;
          if (size > maxBody) {
            reply.raw.statusCode = 413;
            reply.raw.end('Request too large');
            return;
          }
          chunks.push(buffer);
        }
      const response = await iam.handler(
        new Request(requestUrl(request), {
          method: request.method,
          headers: nodeHeaders(request.headers),
          ...(chunks.length ? { body: new Uint8Array(Buffer.concat(chunks)) } : {}),
        }),
      );
      const res = reply.raw;
      res.statusCode = response.status;
      response.headers.forEach((value, key) => {
        if (key !== 'set-cookie') res.setHeader(key, value);
      });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader('set-cookie', cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    }) as FastifyHook);
  };
  // Like fastify-plugin: the hooks and the decorator apply to the whole app, not an encapsulated child.
  Object.assign(plugin, {
    [Symbol.for('skip-override')]: true,
    [Symbol.for('fastify.display-name')]: 'better-iam',
  });

  return {
    resolve: resolveIam,
    /** Register with `app.register(iamFastify.plugin)`. */
    plugin,
    /** The per-request helpers (`request.iam`). */
    helpers: helpersFor,
    /** A `preHandler` requiring a session (and `stepUp`, when given). */
    requireSession: (spec: Pick<GuardSpec<FastifyRequestLike, Session>, 'stepUp'> = {}) =>
      guard(spec) as FastifyHook,
    /** A `preHandler` requiring a session allowed to perform `action` (default resource: the tenant). */
    authorize: (
      action: string,
      spec: Omit<NonNullable<GuardSpec<FastifyRequestLike, Session>['authorize']>, 'action'> &
        Pick<GuardSpec<FastifyRequestLike, Session>, 'stepUp'> = {},
    ) => {
      const { stepUp, ...rule } = spec;
      return guard({
        ...(stepUp ? { stepUp } : {}),
        authorize: { action, ...rule },
      }) as FastifyHook;
    },
    /** `app.setErrorHandler(iamFastify.errorHandler)`: IAM refusals become the JSON envelope; others are rethrown. */
    errorHandler: async (
      error: Error,
      request: FastifyRequestLike,
      reply: FastifyReplyLike,
    ): Promise<unknown> => {
      if (isIamRefusal(error)) return answer(request, reply, error);
      throw error;
    },
  };
}
export type IamFastify<T extends IamLike = IamLike> = ReturnType<typeof createIamFastify<T>>;
export type { IamRequest } from './index.js';
