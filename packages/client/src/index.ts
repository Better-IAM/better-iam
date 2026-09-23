import type { CredentialInput } from '@better-iam/core';

/** HTTP errors preserve the server's stable code without exposing raw response bodies. */
export class IamClientError extends Error {
  /** For `WRONG_REGION`: the region whose deployment serves the organization. */
  region?: string;
  /** For `WRONG_REGION`: the organization's sign-in URL in that region, so a sign-in page can send the person there. */
  location?: string;
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
    /** For `RATE_LIMITED` responses: how long to wait before retrying, from the server's `Retry-After`. */
    readonly retryAfterMs?: number,
    /** The `X-Request-Id` the request carried (see `ClientOptions.requestId`), for support tickets and log lookups. */
    readonly requestId?: string,
  ) {
    super(message);
    this.name = 'IamClientError';
  }
}
export { IamClientError as ClientError };

export interface ClientOptions {
  /** The application's origin. Defaults to the current page origin in a browser. */
  baseURL?: string;
  basePath?: string;
  /**
   * Read an in-memory token when using bearer authentication; never stored by the client. Opaque tokens and
   * IAM-signed session JWTs (from `roles.assume` or `sts.getSessionToken` with `format: 'jwt'`) are both accepted;
   * any other shape fails with `INVALID_TOKEN` before a request is made.
   */
  token?: string | (() => string | undefined | Promise<string | undefined>);
  headers?: HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  fetch?: typeof globalThis.fetch;
  /**
   * Called once per request that the server refused because the presented session can no longer be used, after
   * the error is raised, so an application can send the person to its login page in one place. Exactly these codes
   * trigger it: `UNAUTHENTICATED` (the session lapsed, was revoked, or the token is gone) and
   * `SESSION_NETWORK_MISMATCH` (a session bound to its network presented from another one; signing in again from
   * the new network is the way back). Credential failures such as a wrong password (`INVALID_CREDENTIALS`) never
   * trigger it, and neither do codes the server also raises for sign-in or step-up (`MFA_REQUIRED`,
   * `EMAIL_UNVERIFIED`, `IP_BLOCKED`, …), where a trip to the login page would not help; handle those per call.
   */
  onUnauthenticated?: (error: IamClientError) => void;
  /**
   * Retry a `RATE_LIMITED` response once after the server's `retryAfterMs`, when that wait is at most `maxWaitMs`
   * (five seconds by default); longer waits surface the error unchanged. Off by default. Aborting the call's
   * `signal` during the wait rejects at once with the signal's reason, without a second request.
   */
  retryRateLimited?: boolean | { maxWaitMs?: number };
  /**
   * Send an `X-Request-Id` header on every request (the server echoes it and records it on its `http` spans) and
   * expose it as `IamClientError.requestId`. `true` generates one per request; a function supplies your own.
   */
  requestId?: boolean | (() => string);
}
export interface ClientCallOptions {
  signal?: AbortSignal;
  headers?: HeadersInit;
}
type AnyMethod = (...args: never[]) => unknown;
type IsCredential<T> = Exclude<keyof T, keyof CredentialInput> extends never ? true : false;
type ClientArguments<T extends AnyMethod> =
  Parameters<T> extends [infer First, infer Second, ...unknown[]]
    ? IsCredential<First> extends true
      ? [input: Second, options?: ClientCallOptions]
      : [...Parameters<T>, options?: ClientCallOptions]
    : Parameters<T> extends [infer First]
      ? IsCredential<First> extends true
        ? [options?: ClientCallOptions]
        : [input: First, options?: ClientCallOptions]
      : [options?: ClientCallOptions];
type MfaChallenge = { tenantId: string; challenge: string };
type ClientMethod<T extends AnyMethod, Group, Method> = Group extends 'auth'
  ? Method extends 'beginMfa'
    ? (input?: MfaChallenge, options?: ClientCallOptions) => Promise<Awaited<ReturnType<T>>>
    : Method extends 'confirmMfa'
      ? (
          input: { credential?: MfaChallenge; code: string; rememberDevice?: boolean },
          options?: ClientCallOptions,
        ) => Promise<Awaited<ReturnType<T>>>
      : (...args: ClientArguments<T>) => Promise<Awaited<ReturnType<T>>>
  : (...args: ClientArguments<T>) => Promise<Awaited<ReturnType<T>>>;
export type ClientApi<Api> = {
  [Group in keyof Api]: {
    [Method in keyof Api[Group] as Api[Group][Method] extends AnyMethod
      ? Method
      : never]: Api[Group][Method] extends AnyMethod
      ? ClientMethod<Api[Group][Method], Group, Method>
      : never;
  };
};
export interface ClientTransport {
  /** Escape hatch for plugin endpoints. path is relative to the configured IAM basePath. */
  $request<Output = unknown>(
    path: string,
    input?: unknown,
    options?: ClientCallOptions,
  ): Promise<Output>;
}
type AuthorizeClient<T> = (T extends { authorize: (input: infer Input) => infer Output }
  ? {
      authorize(
        input: Omit<Input, keyof CredentialInput>,
        options?: ClientCallOptions,
      ): Promise<Awaited<Output>>;
    }
  : Record<never, never>) &
  (T extends { authorizeMany: (input: infer Input) => infer Output }
    ? {
        authorizeMany(
          input: Omit<Input, keyof CredentialInput>,
          options?: ClientCallOptions,
        ): Promise<Awaited<Output>>;
      }
    : Record<never, never>) &
  (T extends { listAccessible: (input: infer Input) => infer Output }
    ? {
        listAccessible(
          input: Omit<Input, keyof CredentialInput>,
          options?: ClientCallOptions,
        ): Promise<Awaited<Output>>;
      }
    : Record<never, never>);
export type IamClient<T extends { api: unknown }> = ClientApi<T['api']> &
  ClientTransport &
  AuthorizeClient<T>;

const noInputAuthMethods = new Set([
  'signOut',
  'getSession',
  'listSessions',
  'revokeOtherSessions',
  'beginPasskeyRegistration',
  'listPasskeys',
  'regenerateRecoveryCodes',
  'disableMfa',
  'listTrustedDevices',
  'revokeTrustedDevices',
  'mfaStatus',
]);
/**
 * Methods outside `auth` whose only server parameter is the credential. `ClientArguments` types them as
 * `(options?)`, so the runtime must read their first argument as call options too, never as the request body.
 */
const noInputMethods = new Set(['sts/getCallerIdentity', 'links/list']);
/** Top-level authorization routes that take a plain input instead of a group/method pair. */
const topLevelRoutes = new Set(['authorize', 'authorizeMany', 'listAccessible']);
/**
 * Refusals that end the presented session wherever it is used next, so `onUnauthenticated` fires for them. Codes
 * the server also raises from sign-in or step-up flows (`MFA_REQUIRED`, `EMAIL_UNVERIFIED`, `IP_BLOCKED`, …) stay
 * out: the client cannot tell those apart from a dead session, and a login redirect mid-step-up would lose work.
 */
const sessionEndingCodes = new Set(['UNAUTHENTICATED', 'SESSION_NETWORK_MISMATCH']);
const reserved = new Set([
  'then',
  'catch',
  'finally',
  'toJSON',
  'constructor',
  'prototype',
  '__proto__',
]);
function routeSegment(value: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_-]*$/.test(value) && !reserved.has(value);
}
/**
 * The bearer shapes the server can accept: an opaque token (sessions, API keys, role sessions and session tokens,
 * prefixed `biam_…` or legacy) or an IAM-signed session JWT (three base64url segments, at most 4096 characters).
 * Anything else never leaves the client, so a stray value cannot end up in an `Authorization` header.
 */
function bearerToken(value: string): boolean {
  if (/^[A-Za-z0-9_-]{16,512}$/.test(value)) return true;
  return (
    value.length <= 4096 &&
    /^[A-Za-z0-9_-]{2,1024}\.[A-Za-z0-9_-]{2,3072}\.[A-Za-z0-9_-]{2,1024}$/.test(value)
  );
}

/**
 * Types are inferred from the server instance using a type-only import:
 * const client = createIamClient<typeof iam>({ baseURL: 'https://app.example.com' });
 * const { tenantId } = await client.tenants.lookup({ slug: 'acme' });
 * await client.auth.signIn({ tenantId, email, password });
 * const { results } = await client.authorizeMany({ tenantId, checks });
 * const { resources } = await client.listAccessible({ tenantId, action: 'projects:read', type: 'project' });
 */
export function createIamClient<T extends { api: unknown }>(
  options: ClientOptions = {},
): IamClient<T> {
  const origin = options.baseURL ?? (typeof location === 'object' ? location.origin : undefined);
  if (!origin)
    throw new IamClientError('INVALID_CONFIG', 'baseURL is required outside a browser', 0);
  let base: URL;
  try {
    base = new URL(origin);
  } catch {
    throw new IamClientError('INVALID_CONFIG', 'baseURL must be an absolute HTTP(S) URL', 0);
  }
  if (
    !['http:', 'https:'].includes(base.protocol) ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  )
    throw new IamClientError(
      'INVALID_CONFIG',
      'baseURL must be an HTTP(S) URL without credentials, query, or fragment',
      0,
    );
  const basePath = options.basePath ?? '/api/iam';
  if (!/^\/[A-Za-z0-9_/-]+$/.test(basePath) || basePath.endsWith('/'))
    throw new IamClientError(
      'INVALID_CONFIG',
      'basePath must be an absolute path without a trailing slash',
      0,
    );
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) throw new IamClientError('INVALID_CONFIG', 'A Fetch implementation is required', 0);
  const retryWait =
    options.retryRateLimited === true
      ? 5_000
      : options.retryRateLimited && typeof options.retryRateLimited === 'object'
        ? (options.retryRateLimited.maxWaitMs ?? 5_000)
        : 0;
  const nextRequestId = (): string | undefined => {
    if (typeof options.requestId === 'function') return options.requestId();
    if (options.requestId === true)
      return typeof globalThis.crypto?.randomUUID === 'function'
        ? globalThis.crypto.randomUUID()
        : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
    return undefined;
  };
  // The retry wait honours the call's signal: an aborted call settles at once with the signal's reason (as fetch
  // itself would) instead of holding its caller for the whole server-requested wait and sending a doomed request.
  const aborted = (signal: AbortSignal): unknown =>
    signal.reason ??
    (typeof DOMException === 'function'
      ? new DOMException('This operation was aborted', 'AbortError')
      : Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }));
  const sleep = (ms: number, signal?: AbortSignal) =>
    new Promise<void>((resolve, reject) => {
      if (!signal) return void setTimeout(resolve, ms);
      if (signal.aborted) return reject(aborted(signal));
      const onAbort = () => {
        clearTimeout(timer);
        reject(aborted(signal));
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', onAbort);
        resolve();
      }, ms);
      signal.addEventListener('abort', onAbort, { once: true });
    });

  const request = async <Output>(
    path: string,
    input: unknown = {},
    callOptions: ClientCallOptions = {},
  ): Promise<Output> => {
    try {
      return await attempt<Output>(path, input, callOptions);
    } catch (error) {
      if (
        error instanceof IamClientError &&
        error.code === 'RATE_LIMITED' &&
        retryWait > 0 &&
        error.retryAfterMs !== undefined &&
        error.retryAfterMs <= retryWait
      ) {
        await sleep(error.retryAfterMs, callOptions.signal);
        return attempt<Output>(path, input, callOptions);
      }
      throw error;
    }
  };

  const attempt = async <Output>(
    path: string,
    input: unknown,
    callOptions: ClientCallOptions,
  ): Promise<Output> => {
    if (!path || !path.split('/').every(routeSegment))
      throw new IamClientError(
        'INVALID_PATH',
        'IAM routes must use plain relative path segments',
        0,
      );
    const configuredHeaders =
      typeof options.headers === 'function' ? await options.headers() : options.headers;
    const headers = new Headers(configuredHeaders);
    new Headers(callOptions.headers).forEach((value, key) => headers.set(key, value));
    // These headers are invariant: the server's CSRF boundary requires both.
    headers.set('content-type', 'application/json');
    headers.set('x-better-iam', '1');
    const requestId = nextRequestId();
    if (requestId !== undefined) {
      if (!/^[A-Za-z0-9._:-]{1,128}$/.test(requestId))
        throw new IamClientError('INVALID_CONFIG', 'requestId must be a short plain token', 0);
      headers.set('x-request-id', requestId);
    }
    const fail = (
      code: string,
      message: string,
      status: number,
      retryAfterMs?: number,
    ): IamClientError => {
      const error = new IamClientError(code, message, status, retryAfterMs, requestId);
      if (sessionEndingCodes.has(code) && options.onUnauthenticated) {
        try {
          options.onUnauthenticated(error);
        } catch {
          /* A hook that throws never changes what the caller sees. */
        }
      }
      return error;
    };
    const token = typeof options.token === 'function' ? await options.token() : options.token;
    if (token !== undefined) {
      if (typeof token !== 'string' || !bearerToken(token))
        throw new IamClientError('INVALID_TOKEN', 'Invalid bearer token format', 0);
      headers.set('authorization', `Bearer ${token}`);
    }
    let body: string;
    try {
      body = JSON.stringify(input ?? {});
    } catch {
      throw new IamClientError('INVALID_INPUT', 'Request input must be serializable JSON', 0);
    }
    const response = await fetcher(new URL(`${basePath}/${path}`, base.origin), {
      method: 'POST',
      headers,
      body,
      credentials: 'include',
      redirect: 'error',
      cache: 'no-store',
      signal: callOptions.signal,
    });
    let envelope: unknown;
    try {
      envelope = await response.json();
    } catch {
      throw fail(
        'INVALID_RESPONSE',
        'The IAM server returned an invalid response',
        response.status,
      );
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope))
      throw fail(
        'INVALID_RESPONSE',
        'The IAM server returned an invalid response',
        response.status,
      );
    if ('error' in envelope) {
      const error = envelope.error;
      if (
        error &&
        typeof error === 'object' &&
        'code' in error &&
        typeof error.code === 'string' &&
        'message' in error &&
        typeof error.message === 'string'
      ) {
        const fromBody =
          'retryAfterMs' in error && typeof error.retryAfterMs === 'number'
            ? error.retryAfterMs
            : undefined;
        const header = Number(response.headers.get('retry-after'));
        const failure = fail(
          error.code,
          error.message,
          response.status,
          fromBody ?? (Number.isFinite(header) && header > 0 ? header * 1000 : undefined),
        );
        if ('region' in error && typeof error.region === 'string') failure.region = error.region;
        if (
          'location' in error &&
          typeof error.location === 'string' &&
          /^https?:\/\//.test(error.location)
        )
          failure.location = error.location;
        throw failure;
      }
      throw fail(
        'INVALID_RESPONSE',
        'The IAM server returned an invalid error response',
        response.status,
      );
    }
    if (!response.ok)
      throw fail('HTTP_ERROR', 'The IAM server rejected the request', response.status);
    if (!Object.hasOwn(envelope, 'data'))
      throw fail(
        'INVALID_RESPONSE',
        'The IAM server returned an invalid response',
        response.status,
      );
    return (envelope as { data: Output }).data;
  };

  const groups = new Map<string, object>();
  const transport: ClientTransport = { $request: request };
  return new Proxy(transport, {
    get(target, group: string | symbol) {
      if (group === Symbol.toStringTag) return 'BetterIamClient';
      if (typeof group !== 'string' || reserved.has(group)) return undefined;
      if (group === '$request') return target.$request;
      if (topLevelRoutes.has(group))
        return (input: unknown, callOptions?: ClientCallOptions) =>
          request(group, input, callOptions);
      if (!routeSegment(group)) return undefined;
      let proxy = groups.get(group);
      if (!proxy) {
        proxy = new Proxy(Object.create(null) as object, {
          get(_target, method: string | symbol) {
            if (typeof method !== 'string' || !routeSegment(method)) return undefined;
            if (
              (group === 'auth' && noInputAuthMethods.has(method)) ||
              noInputMethods.has(`${group}/${method}`)
            )
              return (callOptions?: ClientCallOptions) =>
                request(`${group}/${method}`, {}, callOptions);
            return (input?: unknown, callOptions?: ClientCallOptions) =>
              request(`${group}/${method}`, input ?? {}, callOptions);
          },
        });
        groups.set(group, proxy);
      }
      return proxy;
    },
  }) as IamClient<T>;
}
