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

/** The Express (4 or 5) / Connect request fields the middleware reads. */
export type ExpressRequest = IncomingMessage & {
  originalUrl?: string;
  protocol?: string;
  body?: unknown;
  rawBody?: unknown;
  iam?: unknown;
};
export type ExpressNext = (error?: unknown) => void;
export type ExpressMiddleware = (
  req: ExpressRequest,
  res: ServerResponse,
  next: ExpressNext,
) => Promise<void>;

export interface IamExpressOptions extends RequestHelperOptions, GuardOptions {
  /**
   * Path prefixes the IAM server answers (default: its `basePath`). Add protocol mounts outside it, e.g. `'/oauth'`
   * or `'/.well-known'`, so their requests reach `iam.nodeHandler` too.
   */
  serve?: string[];
  /** Where page navigations (GET with `Accept: text/html`) go when signed out; `?next=` carries the path. */
  loginPath?: string;
  /** Where page navigations go when the session must step up (`?next=`, `?reason=`). */
  stepUpPath?: string;
}

const maxBody = 2097152;
function flatten(value: unknown, prefix = '', into = new URLSearchParams()): URLSearchParams {
  if (value && typeof value === 'object' && !Array.isArray(value))
    for (const [key, item] of Object.entries(value))
      flatten(item, prefix ? `${prefix}[${key}]` : key, into);
  else if (Array.isArray(value)) for (const item of value) flatten(item, prefix, into);
  else if (value !== undefined && value !== null) into.append(prefix, String(value));
  return into;
}
/** A body a parser (`express.json()`, `urlencoded`) already consumed, re-serialised; undefined when the stream is intact. */
function consumedBody(req: ExpressRequest): Uint8Array | undefined {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  if (Buffer.isBuffer(req.rawBody)) return new Uint8Array(req.rawBody);
  if (!req.readableEnded && req.body === undefined) return undefined;
  const body = req.body;
  if (body === undefined || body === null) return new Uint8Array();
  if (Buffer.isBuffer(body)) return new Uint8Array(body);
  if (typeof body === 'string') return new TextEncoder().encode(body);
  const type = String(req.headers['content-type'] ?? '').toLowerCase();
  return new TextEncoder().encode(
    type.startsWith('application/x-www-form-urlencoded')
      ? flatten(body).toString()
      : JSON.stringify(body),
  );
}
function requestUrl(req: ExpressRequest): URL {
  const encrypted = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true;
  const protocol = req.protocol ?? (encrypted ? 'https' : 'http');
  return new URL(
    req.originalUrl ?? req.url ?? '/',
    `${protocol}://${req.headers.host ?? 'localhost'}`,
  );
}
function appendSetCookie(res: ServerResponse, header: string): void {
  const current = res.getHeader('set-cookie');
  const list = current === undefined ? [] : Array.isArray(current) ? current : [String(current)];
  res.setHeader('set-cookie', [...list, header]);
}
async function sendResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    if (key !== 'set-cookie') res.setHeader(key, value);
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) res.setHeader('set-cookie', cookies);
  res.end(Buffer.from(await response.arrayBuffer()));
}

/**
 * Express / Connect integration. `middleware` serves the IAM API (through `iam.nodeHandler`, so node protocol mounts
 * such as the OAuth provider work) and gives every other request `req.iam`; `requireSession` and `authorize` are route
 * guards; `errorHandler` answers IAM refusals thrown by your routes.
 *
 * ```ts
 * const iamExpress = createIamExpress(iam, { loginPath: '/login' });
 * app.use(iamExpress.middleware); // before express.json()
 * app.get('/projects/:id', iamExpress.authorize('projects:read', { resource: (req) => ({ type: 'project', id: req.params.id }) }), handler);
 * app.use(iamExpress.errorHandler);
 * ```
 */
export function createIamExpress<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamExpressOptions = {},
) {
  type Session = SessionOf<T>;
  const resolveIam = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const state = new WeakMap<object, IamRequest<T>>();
  const helpersFor = (req: ExpressRequest, res: ServerResponse): IamRequest<T> => {
    const existing = state.get(req);
    if (existing) return existing;
    const created = createRequestHelpers(
      resolveIam,
      {
        url: requestUrl(req),
        headers: nodeHeaders(req.headers),
        setCookie: (header) => appendSetCookie(res, header),
      },
      options,
    );
    state.set(req, created);
    req.iam = created;
    return created;
  };
  const refuse = (req: ExpressRequest, res: ServerResponse, error: unknown, next: ExpressNext) => {
    if (!isIamRefusal(error) || res.headersSent) return next(error);
    const answer = refusalResponse(
      error,
      { url: requestUrl(req), headers: nodeHeaders(req.headers), method: req.method ?? 'GET' },
      { loginPath: options.loginPath, stepUpPath: options.stepUpPath },
    );
    if ('redirect' in answer) {
      res.statusCode = 303;
      res.setHeader('location', answer.redirect);
      res.end();
      return;
    }
    res.statusCode = answer.status;
    res.setHeader('content-type', 'application/json');
    res.setHeader('cache-control', 'no-store');
    res.end(answer.body);
  };
  const guard =
    (spec: GuardSpec<ExpressRequest, Session>): ExpressMiddleware =>
    async (req, res, next) => {
      try {
        const iam = await resolveIam();
        await enforceGuard(
          helpersFor(req, res),
          req,
          spec,
          options.csrf === false
            ? undefined
            : {
                method: req.method ?? 'GET',
                url: requestUrl(req),
                headers: nodeHeaders(req.headers),
                trustedOrigins: [iam.endpoint?.origin, ...(options.trustedOrigins ?? [])],
              },
        );
      } catch (error) {
        return refuse(req, res, error, next);
      }
      next();
    };

  return {
    resolve: resolveIam,
    /** The per-request helpers (`req.iam`), created on first use. */
    helpers: helpersFor,
    /** Serves the IAM API under `serve` prefixes and attaches `req.iam` to everything else. Mount before body parsers. */
    middleware: (async (req, res, next) => {
      try {
        const iam = await resolveIam();
        const url = requestUrl(req);
        const prefixes = options.serve ?? [
          options.basePath ?? iam.endpoint?.basePath ?? '/api/iam',
        ];
        if (prefixes.some((prefix) => underPath(url.pathname, prefix))) {
          const body = consumedBody(req);
          if (body === undefined && iam.nodeHandler) {
            // Express strips a mount path from req.url; the IAM server routes on the full path.
            req.url = req.originalUrl ?? req.url;
            await (iam.nodeHandler as (req: IncomingMessage, res: ServerResponse) => Promise<void>)(
              req,
              res,
            );
            return;
          }
          if (body && body.length > maxBody) {
            res.statusCode = 413;
            res.end('Request too large');
            return;
          }
          const headers = nodeHeaders(req.headers);
          if (body !== undefined) headers.set('content-length', String(body.length));
          await sendResponse(
            res,
            await iam.handler(
              new Request(url, {
                method: req.method ?? 'GET',
                headers,
                ...(body?.length ? { body: body as unknown as BodyInit } : {}),
              }),
            ),
          );
          return;
        }
        helpersFor(req, res);
      } catch (error) {
        return next(error);
      }
      next();
    }) satisfies ExpressMiddleware,
    /** Requires a session (and `stepUp`, when given). */
    requireSession: (spec: Pick<GuardSpec<ExpressRequest, Session>, 'stepUp'> = {}) => guard(spec),
    /** Requires a session allowed to perform `action` (default resource: the tenant). */
    authorize: (
      action: string,
      spec: Omit<NonNullable<GuardSpec<ExpressRequest, Session>['authorize']>, 'action'> &
        Pick<GuardSpec<ExpressRequest, Session>, 'stepUp'> = {},
    ) => {
      const { stepUp, ...rule } = spec;
      return guard({ ...(stepUp ? { stepUp } : {}), authorize: { action, ...rule } });
    },
    /** Error middleware: IAM refusals become the JSON error envelope (or a login / step-up redirect for pages). */
    errorHandler: (error: unknown, req: ExpressRequest, res: ServerResponse, next: ExpressNext) =>
      refuse(req, res, error, next),
  };
}
export type IamExpress<T extends IamLike = IamLike> = ReturnType<typeof createIamExpress<T>>;
export type { IamRequest } from './index.js';
