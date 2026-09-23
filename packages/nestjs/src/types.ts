import type { AuthenticatedPrincipal, Decision } from '@better-iam/core';
import type { BetterIam } from '@better-iam/server';

/** The server surface the Nest integration uses; a `betterIam()` instance satisfies it. */
export type IamInstance = Pick<
  BetterIam,
  'authenticate' | 'authorize' | 'authorizeMany' | 'listAccessible' | 'handler' | 'api' | 'events'
> &
  Partial<Pick<BetterIam, 'endpoint'>>;

/** The part of a Node, Express, or Fastify request the integration reads. */
export interface RequestLike {
  headers: Headers | Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  originalUrl?: string;
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  body?: unknown;
}

export type CredentialKind = AuthenticatedPrincipal['session']['kind'];
export type ResourceTarget = { type: string; id: string };

/**
 * Where a value comes from on the request: a route parameter, query string key, body field, header, resolver argument, a fixed string,
 * or a function of the request and the authenticated principal.
 */
export type ValueSource =
  | string
  | { param: string }
  | { query: string }
  | { body: string }
  | { header: string }
  /** A GraphQL resolver argument or a field of the WebSocket message. */
  | { arg: string }
  | ((request: RequestLike, principal: AuthenticatedPrincipal) => string | Promise<string>);

/** The resource an `@Authorize` rule is checked against; defaults to the tenant itself (`iam/{tenantId}`). */
export type ResourceSource =
  | { type: string; id: ValueSource }
  | ((
      request: RequestLike,
      principal: AuthenticatedPrincipal,
    ) => ResourceTarget | Promise<ResourceTarget>);

export interface AuthorizeRule {
  action: string;
  resource?: ResourceSource;
  /** Overrides the module's tenant resolution for this rule. */
  tenant?: ValueSource;
}

export interface CsrfOptions {
  /** Origins allowed to send cookie-authenticated unsafe requests; the request's own host is always allowed. */
  trustedOrigins?: string[];
}

export interface IamModuleOptions {
  iam: IamInstance;
  /**
   * Resolves the tenant a rule is evaluated in when the rule does not name one. The default reads the `tenantId` route
   * parameter, then the `x-tenant-id` header, then falls back to the tenant of the caller's session.
   */
  tenant?: ValueSource;
  /**
   * Rejects cookie-authenticated POST/PUT/PATCH/DELETE requests whose Origin is foreign (default on). Bearer tokens
   * and API keys are unaffected because browsers never attach them implicitly.
   */
  csrf?: boolean | CsrfOptions;
  /**
   * Path the IAM HTTP handler is mounted at when `mount` is enabled; defaults to the server's `basePath`. Relative to
   * the application's global prefix, which Nest also applies to middleware.
   */
  mountPath?: string;
  /**
   * Runs `iam.events.dispatch()` on this interval while the application is up, delivering queued audit events to
   * `@OnIamEvent` handlers, plugins, and `events.onEvent`. Leave unset when a separate worker dispatches.
   */
  dispatchIntervalMs?: number;
}

export interface IamRequestState {
  principal: AuthenticatedPrincipal | null;
  tenantId?: string;
  /** Decisions made by `@Authorize` rules for this request, in rule order. */
  decisions: { action: string; tenantId: string; resource: ResourceTarget; decision: Decision }[];
}
