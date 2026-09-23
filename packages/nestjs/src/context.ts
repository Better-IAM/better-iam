import { HttpException, type ExecutionContext } from '@nestjs/common';
import type { AuthenticatedPrincipal, CredentialInput } from '@better-iam/core';
import type { IamRequestState, RequestLike, ValueSource } from './types.js';

/** Injection token for the `betterIam()` instance. */
export const IAM_INSTANCE = 'BETTER_IAM_INSTANCE';
/** Injection token for the resolved `IamModuleOptions`. */
export const IAM_OPTIONS = 'BETTER_IAM_OPTIONS';
/** Injection token for the resolved `IamAssertionOptions`. */
export const IAM_ASSERTION_OPTIONS = 'BETTER_IAM_ASSERTION_OPTIONS';

export const PUBLIC_KEY = 'better-iam:public';
export const AUTHORIZE_KEY = 'better-iam:authorize';
export const MFA_KEY = 'better-iam:mfa';
export const CREDENTIALS_KEY = 'better-iam:credentials';
export const ASSERTION_KEY = 'better-iam:assertion';
export const EVENT_KEY = 'better-iam:event';

const authenticationCodes = new Set([
  'UNAUTHENTICATED',
  'MFA_REQUIRED',
  'EMAIL_UNVERIFIED',
  'TENANT_INACTIVE',
  'TENANT_UNAVAILABLE',
  'IMPERSONATION_RESTRICTED',
]);

/** Duck-typed so errors from a second copy of `@better-iam/core` are still recognised. */
export function isIamError(error: unknown): error is Error & { code: string; status: number } {
  return (
    error instanceof Error &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { status?: unknown }).status === 'number'
  );
}
/** True for the errors authentication raises when a request carries no usable credential. */
export function isAuthenticationError(error: unknown): boolean {
  return isIamError(error) && authenticationCodes.has(error.code);
}
/** The HTTP exception Nest renders for an IAM error: the server's own `{ error: { code, message } }` body and status. */
export function toHttpException(error: Error & { code: string; status: number }): HttpException {
  return new HttpException({ error: { code: error.code, message: error.message } }, error.status, {
    cause: error,
  });
}
export function iamHttpError(code: string, message: string, status: number): HttpException {
  return new HttpException({ error: { code, message } }, status);
}

/** Normalises Node-style or Fetch headers into a `Headers` instance. */
export function headersOf(request: Pick<RequestLike, 'headers'>): Headers {
  if (request.headers instanceof Headers) return request.headers;
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(key, String(item));
  }
  return headers;
}
export function credentialOf(request: Pick<RequestLike, 'headers'>): CredentialInput {
  return { headers: headersOf(request) };
}

/**
 * The request behind an execution context: HTTP (Express and Fastify), GraphQL (the `req`/`request` on the context
 * object), and WebSocket gateways (the socket.io handshake). RPC transports carry no HTTP credential and return null.
 */
export interface RequestScope {
  request: RequestLike;
  /** Identity of the request for per-request state. */
  key: object;
  /** GraphQL resolver arguments or the WebSocket message, for `{ arg }` value sources. */
  args?: Record<string, unknown>;
}
export function requestOf(context: ExecutionContext): RequestScope | null {
  const type = context.getType<string>();
  if (type === 'http') {
    const request = context.switchToHttp().getRequest<RequestLike>();
    return request ? { request, key: request } : null;
  }
  if (type === 'graphql') {
    const gql = context.getArgByIndex<Record<string, unknown> | undefined>(2);
    const request = (gql?.req ??
      gql?.request ??
      (gql?.reply as { request?: unknown } | undefined)?.request) as RequestLike | undefined;
    const args = context.getArgByIndex<Record<string, unknown> | undefined>(1);
    return request?.headers ? { request, key: request, args: args ?? undefined } : null;
  }
  if (type === 'ws') {
    const client = context.switchToWs().getClient<Record<string, unknown> | undefined>();
    const handshake = (client?.handshake ?? client?.request ?? client?.upgradeReq) as
      | RequestLike
      | undefined;
    if (!handshake?.headers) return null;
    const data = context.switchToWs().getData<unknown>();
    // Each message is authorised on its own; the connection object would otherwise carry a stale principal.
    return data && typeof data === 'object'
      ? { request: handshake, key: data, args: data as Record<string, unknown> }
      : { request: handshake, key: client! };
  }
  return null;
}

const states = new WeakMap<object, IamRequestState>();
export function stateOf(key: object): IamRequestState | undefined {
  return states.get(key);
}
export function setState(key: object, state: IamRequestState): void {
  states.set(key, state);
}
export function stateFromContext(context: ExecutionContext): IamRequestState | undefined {
  const found = requestOf(context);
  return found ? states.get(found.key) : undefined;
}

function pick(record: unknown, name: string): unknown {
  return record && typeof record === 'object'
    ? (record as Record<string, unknown>)[name]
    : undefined;
}
const defaultTenant: ValueSource[] = [{ param: 'tenantId' }, { header: 'x-tenant-id' }];
/**
 * The tenant a rule is evaluated in: the rule's own source, else the module's `tenant` option, else the `tenantId`
 * route parameter or `x-tenant-id` header, and finally the tenant of the caller's session.
 */
export async function resolveTenant(
  source: ValueSource | undefined,
  moduleSource: ValueSource | undefined,
  request: RequestLike,
  principal: AuthenticatedPrincipal,
  args?: Record<string, unknown>,
): Promise<string> {
  for (const candidate of source ? [source] : moduleSource ? [moduleSource] : defaultTenant) {
    const tenantId = await resolveValue(candidate, request, principal, args);
    if (tenantId) return tenantId;
  }
  return principal.session.tenantId;
}

/** Resolves a `ValueSource` against a request; missing values resolve to undefined. */
export async function resolveValue(
  source: ValueSource,
  request: RequestLike,
  principal: AuthenticatedPrincipal,
  args?: Record<string, unknown>,
): Promise<string | undefined> {
  let value: unknown;
  if (typeof source === 'string') value = source;
  else if (typeof source === 'function') value = await source(request, principal);
  else if ('param' in source) value = pick(request.params, source.param);
  else if ('query' in source) value = pick(request.query, source.query);
  else if ('body' in source) value = pick(request.body, source.body);
  else if ('arg' in source) value = pick(args, source.arg);
  else value = headersOf(request).get(source.header) ?? undefined;
  if (Array.isArray(value)) value = value[0];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
