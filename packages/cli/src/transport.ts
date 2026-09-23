import { IamError, type CredentialInput } from '@better-iam/core';
import {
  authenticatedAuthMethods,
  publicApiMethods,
  publicAuthMethods,
  routeGroups,
  type BetterIam,
} from '@better-iam/server';
import { createIamClient } from '@better-iam/client';
import { usageError } from './errors.js';

/**
 * Calls the IAM HTTP API surface by route (`roles/create`, `auth/getSession`, `authorize`): in process against a
 * configured instance, or over HTTPS against a running server. Both expose exactly the routes the HTTP handler
 * serves, with the same credential rules, so a command behaves the same locally and remotely.
 */
export interface ApiTransport {
  readonly mode: 'local' | 'remote';
  /** The configuration file or endpoint URL the calls go to, for messages. */
  readonly target: string;
  call<Output = unknown>(path: string, input?: Record<string, unknown>): Promise<Output>;
}

type Callable = (...args: unknown[]) => Promise<unknown>;
const segment = /^[A-Za-z][A-Za-z0-9_-]*$/;
const topLevel = new Set(['authorize', 'authorizeMany', 'listAccessible']);

/** Splits `roles.create`, `roles/create`, or `plugins/reports/summary` into a route path; refuses anything else. */
export function routePath(route: string): string {
  const path = route.includes('/') ? route : route.replace('.', '/');
  const parts = path.split('/');
  if (!parts.every((part) => segment.test(part)) || (parts.length > 2 && parts[0] !== 'plugins'))
    throw usageError(`${route} is not an API route like roles.create or auth.getSession`);
  if (parts.length === 1 && !topLevel.has(path))
    throw usageError(
      `${route} names no method; use group.method (for example roles.list), or api --list ${route}`,
    );
  return path;
}

/** Whether a route needs no credential over HTTP (sign-in ceremonies, invitation acceptance, discovery). */
export function isPublicRoute(path: string): boolean {
  const [group, method] = path.split('/');
  return group === 'auth' ? publicAuthMethods.has(method ?? '') : publicApiMethods.has(path);
}

const notFound = () => new IamError('NOT_FOUND', 'Endpoint not found', 404);

/** Results as the HTTP API returns them: JSON values only (no `undefined`, dates as strings). */
const asJson = (value: unknown): unknown =>
  value === undefined ? null : JSON.parse(JSON.stringify(value));

/**
 * In-process dispatch mirroring the HTTP router: only the routes it serves, public routes without the credential,
 * everything else with it. There is no request-size limit here, unlike HTTP's 64 KiB, so large configuration files
 * apply locally in one call.
 */
async function dispatch(
  iam: BetterIam,
  credential: CredentialInput,
  path: string,
  body: Record<string, unknown>,
): Promise<unknown> {
  // The same named fields the HTTP router passes, so body keys such as `headers` never reach authentication.
  if (path === 'authorize') {
    const resource =
      body.resource && typeof body.resource === 'object'
        ? (body.resource as Record<string, unknown>)
        : {};
    return iam.authorize({
      ...credential,
      tenantId: body.tenantId as string,
      action: body.action as string,
      resource: { type: resource.type as string, id: resource.id as string },
    });
  }
  if (path === 'authorizeMany')
    return iam.authorizeMany({
      ...credential,
      tenantId: body.tenantId as string,
      checks: body.checks as { action: string; resource: { type: string; id: string } }[],
    });
  if (path === 'listAccessible')
    return iam.listAccessible({
      ...credential,
      tenantId: body.tenantId as string,
      action: body.action as string,
      type: body.type as string,
      limit: body.limit as number | undefined,
      offset: body.offset as number | undefined,
    });
  const [group, method, ...rest] = path.split('/');
  if (group === 'plugins')
    return iam.callPlugin(credential, {
      pluginId: method ?? '',
      path: rest.join('/'),
      tenantId: typeof body.tenantId === 'string' ? body.tenantId : '',
      input: body,
    });
  if (!group || !method || rest.length) throw notFound();
  const api = iam.api as unknown as Record<string, Record<string, Callable>>;
  if (group === 'auth') {
    const fn = Object.hasOwn(api.auth!, method) ? api.auth![method] : undefined;
    if (!fn) throw notFound();
    if (method === 'beginMfa')
      return fn(
        typeof body.challenge === 'string'
          ? { tenantId: body.tenantId, challenge: body.challenge }
          : credential,
      );
    if (method === 'confirmMfa') {
      const nested =
        body.credential && typeof body.credential === 'object'
          ? (body.credential as Record<string, unknown>)
          : {};
      return fn({
        credential:
          typeof nested.challenge === 'string'
            ? { tenantId: nested.tenantId, challenge: nested.challenge }
            : credential,
        code: body.code,
        rememberDevice: body.rememberDevice === true,
      });
    }
    if (publicAuthMethods.has(method)) return fn(body);
    if (authenticatedAuthMethods.has(method)) return fn(credential, body);
    throw notFound();
  }
  if (!routeGroups.has(group)) throw notFound();
  const target = api[group];
  const fn = target && Object.hasOwn(target, method) ? target[method] : undefined;
  if (!fn) throw notFound();
  return publicApiMethods.has(path) ? fn(body) : fn(credential, body);
}

/**
 * Calls API routes in process on a configured instance, as `token` (or with no credential), exposing exactly the
 * routes and credential rules of the HTTP handler; what token commands use without `--url`.
 */
export function localTransport(iam: BetterIam, target: string, token?: string): ApiTransport {
  const credential: CredentialInput = token ? { token } : {};
  return {
    mode: 'local',
    target,
    async call<Output>(path: string, input: Record<string, unknown> = {}) {
      return asJson(await dispatch(iam, credential, path, input)) as Output;
    },
  };
}

/** `https://iam.example.com` (default base path `/api/iam`) or the full endpoint `https://host/custom/iam`. */
export function parseEndpoint(url: string): { origin: string; basePath: string; url: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw usageError(`--url ${url} is not an absolute http(s) URL`);
  }
  if (
    !['http:', 'https:'].includes(parsed.protocol) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  )
    throw usageError('--url must be an http(s) URL without credentials, query, or fragment');
  // Passwords and bearer tokens never travel in clear text; the server itself requires HTTPS outside localhost too.
  if (
    parsed.protocol === 'http:' &&
    !['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname) &&
    !parsed.hostname.endsWith('.localhost')
  )
    throw usageError(
      `--url ${parsed.origin} must use https (plain http is allowed for localhost only)`,
    );
  const path = parsed.pathname.replace(/\/+$/, '');
  const basePath = path || '/api/iam';
  return { origin: parsed.origin, basePath, url: `${parsed.origin}${basePath}` };
}

/** Two endpoint URLs name the same IAM API (origin and base path), however they were written. */
export function sameEndpoint(a: string, b: string): boolean {
  try {
    return parseEndpoint(a).url === parseEndpoint(b).url;
  } catch {
    return false;
  }
}

/**
 * Calls API routes on a running IAM server over HTTP(S) with a bearer token, through the typed client (request IDs,
 * one retry after a short rate limit); what token commands use with `--url` or a profile saved against a server.
 */
export function remoteTransport(
  url: string,
  token: string | undefined,
  fetcher?: typeof globalThis.fetch,
): ApiTransport {
  const endpoint = parseEndpoint(url);
  const client = createIamClient<{ api: unknown }>({
    baseURL: endpoint.origin,
    basePath: endpoint.basePath,
    ...(token ? { token } : {}),
    ...(fetcher ? { fetch: fetcher } : {}),
    requestId: true,
    retryRateLimited: true,
  });
  return {
    mode: 'remote',
    target: endpoint.url,
    call<Output>(path: string, input: Record<string, unknown> = {}) {
      return client.$request<Output>(path, input);
    },
  };
}

/** Every route the HTTP API serves for an instance, with whether it needs a credential. */
export function listRoutes(iam: BetterIam): { route: string; access: 'public' | 'token' }[] {
  const api = iam.api as unknown as Record<string, Record<string, unknown>>;
  const routes: { route: string; access: 'public' | 'token' }[] = [...topLevel].map((route) => ({
    route,
    access: 'token',
  }));
  for (const method of Object.keys(api.auth ?? {}))
    if (publicAuthMethods.has(method) || authenticatedAuthMethods.has(method))
      routes.push({
        route: `auth/${method}`,
        access: publicAuthMethods.has(method) ? 'public' : 'token',
      });
  for (const group of routeGroups)
    for (const method of Object.keys(api[group] ?? {}))
      if (typeof api[group]![method] === 'function')
        routes.push({
          route: `${group}/${method}`,
          access: publicApiMethods.has(`${group}/${method}`) ? 'public' : 'token',
        });
  return routes.sort((a, b) => a.route.localeCompare(b.route));
}
