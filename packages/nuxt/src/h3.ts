import type { CredentialInput } from '@better-iam/core';

/** The server surface these helpers use; a `betterIam()` instance satisfies it. */
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
  initialize?(): Promise<unknown>;
  require(
    request: CredentialInput & { tenantId: string; action: string; resource: ResourceRef },
  ): Promise<void>;
  authorizeMany(
    request: CredentialInput & { tenantId: string; checks: AuthorizeCheck[] },
  ): Promise<{ results: (AuthorizeCheck & { allowed: boolean; reason: string })[] }>;
  listAccessible?(
    request: CredentialInput & {
      tenantId: string;
      action: string;
      type: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<unknown>;
}
/**
 * Type registry the Nuxt module augments with the app's IAM instance (`iam: typeof iam`), so server utils and composables
 * return its concrete session type. Outside Nuxt it stays empty and the helpers fall back to `IamLike`.
 */
export interface BetterIamRegister {}
export type RegisteredIam = BetterIamRegister extends { iam: infer T extends IamLike }
  ? T
  : IamLike;

export interface ResourceRef {
  type: string;
  id: string;
}
export interface AuthorizeCheck {
  action: string;
  resource: ResourceRef;
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
type AccessibleOf<T extends IamLike> = T extends {
  listAccessible(...args: never[]): infer Result;
}
  ? Awaited<Result>
  : never;

/**
 * The parts of an h3 event the helpers read. h3 v2 events carry a Web `Request` in `req`; h3 v1 events expose
 * `headers`, `web.request` on edge presets, and the Node request in `node.req`.
 */
export interface H3EventLike {
  context: Record<string, unknown>;
  req?: unknown;
  headers?: unknown;
  web?: { request?: Request };
  node?: { req: NodeRequestLike };
}
interface NodeRequestLike extends AsyncIterable<unknown> {
  headers: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  originalUrl?: string;
  socket?: { encrypted?: boolean };
}

/** An error h3 understands in both majors (`statusCode` for v1, `status` for v2); `data.code` carries the IAM code. */
export class IamH3Error extends Error {
  /** h3 v1 treats errors whose constructor carries this flag as its own (handled, not logged as unhandled). */
  static readonly __h3_error__ = true;
  readonly fatal = false;
  readonly unhandled = false;
  readonly statusCode: number;
  readonly status: number;
  readonly statusMessage: string;
  readonly data: { code: string };
  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'IamH3Error';
    this.statusCode = status;
    this.status = status;
    this.statusMessage = code;
    this.data = { code };
  }
}

export interface IamH3Options {
  /** Converts an event into a Web request for the IAM handler; pass h3's `toWebRequest` when available. */
  toRequest?: (event: never) => Request | Promise<Request>;
  /** Builds the errors thrown by `requireSession` and `require`; pass h3's `createError` to get its error class. */
  createError?: (input: {
    statusCode: number;
    statusMessage: string;
    message: string;
    data: { code: string };
  }) => Error;
}

const authenticationCodes = new Set([
  'UNAUTHENTICATED',
  'MFA_REQUIRED',
  'EMAIL_UNVERIFIED',
  'TENANT_INACTIVE',
  'TENANT_UNAVAILABLE',
]);
function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
    ? error.code
    : undefined;
}
function errorStatus(error: unknown): number | undefined {
  return error && typeof error === 'object' && 'status' in error && typeof error.status === 'number'
    ? error.status
    : undefined;
}
/** True for the errors `getSession` raises when there is no usable session. */
export function isAuthenticationError(error: unknown): boolean {
  const code = errorCode(error);
  return code !== undefined && authenticationCodes.has(code);
}

/** The request headers of an h3 v1 or v2 event. */
export function eventHeaders(event: H3EventLike): Headers {
  if (event.req instanceof Request) return event.req.headers;
  if (event.headers instanceof Headers) return event.headers;
  if (event.web?.request) return event.web.request.headers;
  const headers = new Headers();
  for (const [name, value] of Object.entries(event.node?.req.headers ?? {})) {
    if (Array.isArray(value)) for (const item of value) headers.append(name, item);
    else if (value !== undefined) headers.set(name, value);
  }
  return headers;
}

/** A Web request for an h3 v1 or v2 event; the Node fallback buffers the body, so call it before anything reads it. */
export async function eventRequest(event: H3EventLike): Promise<Request> {
  if (event.req instanceof Request) return event.req;
  if (event.web?.request) return event.web.request;
  const node = event.node?.req;
  if (!node) throw new Error('Unsupported h3 event: no Web or Node request');
  const headers = eventHeaders(event);
  const url = new URL(
    node.originalUrl ?? node.url ?? '/',
    `${node.socket?.encrypted ? 'https' : 'http'}://${headers.get('host') ?? 'localhost'}`,
  );
  const method = (node.method ?? 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return new Request(url, { method, headers });
  const chunks: Uint8Array[] = [];
  for await (const chunk of node)
    chunks.push(
      typeof chunk === 'string' ? new TextEncoder().encode(chunk) : (chunk as Uint8Array),
    );
  const body = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Request(url, { method, headers, body });
}

const sessionKey = Symbol.for('better-iam.h3.session');

/**
 * Server helpers for h3 and Nitro (Nuxt server routes, standalone Nitro, or h3 apps): read the session from the request
 * cookies, enforce before handling, batch advisory decisions, and mount the IAM handler. Sessions are memoized per event.
 */
export function createIamH3<T extends IamLike>(
  source: T | (() => T | Promise<T>),
  options: IamH3Options = {},
) {
  const resolve = async (): Promise<T> =>
    typeof source === 'function' ? await (source as () => T | Promise<T>)() : source;
  const toRequest = (options.toRequest ?? eventRequest) as (
    event: H3EventLike,
  ) => Request | Promise<Request>;
  const fail = (code: string, message: string, status: number): Error =>
    options.createError
      ? options.createError({ statusCode: status, statusMessage: code, message, data: { code } })
      : new IamH3Error(code, message, status);
  const credential = (event: H3EventLike): CredentialInput => ({ headers: eventHeaders(event) });
  const getSession = (event: H3EventLike): Promise<SessionOf<T> | null> => {
    const memo = event.context as Record<PropertyKey, unknown>;
    const cached = memo[sessionKey] as Promise<SessionOf<T> | null> | undefined;
    if (cached) return cached;
    const pending = (async (): Promise<SessionOf<T> | null> => {
      try {
        return (await (await resolve()).api.auth.getSession(credential(event))) as SessionOf<T>;
      } catch (error) {
        if (isAuthenticationError(error)) return null;
        throw error;
      }
    })();
    memo[sessionKey] = pending;
    return pending;
  };
  const translate = (error: unknown): unknown => {
    const code = errorCode(error);
    const status = errorStatus(error);
    if (code === undefined || status === undefined) return error;
    return fail(code, error instanceof Error ? error.message : code, status);
  };
  return {
    resolve,
    credential,
    /** The current session, or null when the request carries no usable credential. Memoized on the event. */
    getSession,
    /** The current session, or a 401 error (`data.code` is `UNAUTHENTICATED`). */
    async requireSession(event: H3EventLike): Promise<SessionOf<T>> {
      const session = await getSession(event);
      if (session) return session;
      throw fail('UNAUTHENTICATED', 'A session is required', 401);
    },
    /** Enforces one action; denial throws an h3-compatible error with the IAM status (401/403/429) and code. */
    async require(
      event: H3EventLike,
      input: { tenantId: string; action: string; resource?: ResourceRef },
    ): Promise<void> {
      const iam = await resolve();
      try {
        await iam.require({
          ...credential(event),
          tenantId: input.tenantId,
          action: input.action,
          resource: input.resource ?? { type: 'iam', id: input.tenantId },
        });
      } catch (error) {
        throw translate(error);
      }
    },
    /** Advisory decisions keyed `${action}@${type}/${id}`; every key is false when the request is not authenticated. */
    async can(
      event: H3EventLike,
      input: { tenantId: string; checks: { action: string; resource?: ResourceRef }[] },
    ): Promise<Record<string, boolean>> {
      const checks = input.checks.map((check) => ({
        action: check.action,
        resource: check.resource ?? { type: 'iam', id: input.tenantId },
      }));
      const key = (check: AuthorizeCheck) =>
        `${check.action}@${check.resource.type}/${check.resource.id}`;
      try {
        const { results } = await (
          await resolve()
        ).authorizeMany({ ...credential(event), tenantId: input.tenantId, checks });
        return Object.fromEntries(results.map((result) => [key(result), result.allowed]));
      } catch (error) {
        if (errorCode(error) !== undefined)
          return Object.fromEntries(checks.map((check) => [key(check), false]));
        throw error;
      }
    },
    /** A short-lived signed assertion about the caller for a downstream service (`iam:assertions:create` on `iam/{audience}`). */
    async assertion(event: H3EventLike, input: AssertionInput): Promise<AssertionOf<T>> {
      const iam = await resolve();
      if (!iam.api.assertions) throw new Error('This IAM server does not issue assertions');
      try {
        return (await iam.api.assertions.issue(credential(event), input)) as AssertionOf<T>;
      } catch (error) {
        throw translate(error);
      }
    },
    /**
     * A session client bound to one event, shaped like the browser client the Vue bindings use, so server rendering
     * can load the session and advisory decisions in process (the HTTP API refuses cookie requests without `Origin`).
     */
    bind(event: H3EventLike) {
      return {
        auth: {
          getSession: async (): Promise<SessionOf<T>> => {
            const session = await getSession(event);
            if (session) return session;
            throw Object.assign(new Error('A session is required'), {
              code: 'UNAUTHENTICATED',
              status: 401,
            });
          },
          signOut: async (): Promise<never> => {
            throw new Error('Sign out from the browser; server rendering cannot clear cookies');
          },
        },
        authorizeMany: async (request: { tenantId: string; checks: AuthorizeCheck[] }) =>
          (await resolve()).authorizeMany({ ...credential(event), ...request }),
        listAccessible: async (request: {
          tenantId: string;
          action: string;
          type: string;
          limit?: number;
          offset?: number;
        }): Promise<AccessibleOf<T>> => {
          const iam = await resolve();
          if (!iam.listAccessible)
            throw new Error('This IAM server does not list accessible resources');
          return (await iam.listAccessible({
            ...credential(event),
            ...request,
          })) as AccessibleOf<T>;
        },
      };
    },
    /** The IAM HTTP handler for an h3 route (`/api/iam/**`); returns the Web `Response`, which h3 sends as is. */
    async handler(event: H3EventLike): Promise<Response> {
      return (await resolve()).handler(await toRequest(event));
    },
  };
}
export type IamH3<T extends IamLike = IamLike> = ReturnType<typeof createIamH3<T>>;
