import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AuthenticatedPrincipal } from '@better-iam/core';
import {
  AUTHORIZE_KEY,
  CREDENTIALS_KEY,
  IAM_OPTIONS,
  MFA_KEY,
  PUBLIC_KEY,
  credentialOf,
  headersOf,
  iamHttpError,
  isAuthenticationError,
  isIamError,
  requestOf,
  type RequestScope,
  resolveTenant,
  resolveValue,
  setState,
  stateOf,
  toHttpException,
} from './context.js';
import type {
  AuthorizeRule,
  CredentialKind,
  IamModuleOptions,
  IamRequestState,
  RequestLike,
  ResourceTarget,
} from './types.js';

const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Authenticates every request it guards and enforces the handler's metadata: `@Public()`, `@Credentials()`,
 * `@RequireMfa()`, and `@Authorize()` rules. Failures render as the IAM server's `{ error: { code, message } }` body
 * with its status (401 unauthenticated, 403 denied, 429 rate limited).
 */
@Injectable()
export class IamGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(IAM_OPTIONS) private readonly options: IamModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, targets) === true;
    const kinds = this.reflector.getAllAndOverride<CredentialKind[] | undefined>(
      CREDENTIALS_KEY,
      targets,
    );
    const requiresMfa = this.reflector.getAllAndOverride<boolean>(MFA_KEY, targets) === true;
    // Class rules run before method rules; all of them must allow.
    const rules = [
      ...((Reflect.getMetadata(AUTHORIZE_KEY, context.getClass()) as AuthorizeRule[]) ?? []),
      ...((Reflect.getMetadata(AUTHORIZE_KEY, context.getHandler()) as AuthorizeRule[]) ?? []),
    ];
    // `@Public()` admits anonymous callers only where nothing else is required: a handler that also carries
    // `@Credentials`, `@RequireMfa` or `@Authorize` (on itself or its class) needs a principal to check them against.
    const anonymousAllowed = isPublic && !kinds && !requiresMfa && rules.length === 0;
    const found = requestOf(context);
    if (!found) {
      if (anonymousAllowed) return true;
      throw iamHttpError('UNAUTHENTICATED', 'This transport carries no IAM credential', 401);
    }
    const { request, key } = found;
    try {
      const principal = await this.principal(request, key, anonymousAllowed);
      const state: IamRequestState = {
        principal,
        tenantId: principal?.session.tenantId,
        decisions: [],
      };
      setState(key, state);
      if (!principal) {
        if (anonymousAllowed) return true;
        throw iamHttpError('UNAUTHENTICATED', 'Authentication is required', 401);
      }
      // GraphQL over HTTP carries the same ambient cookies as a plain HTTP handler (multipart posts included).
      const type = context.getType<string>();
      if (type === 'http' || type === 'graphql') this.checkCsrf(request);
      if (kinds && !kinds.includes(principal.session.kind))
        throw iamHttpError(
          'CREDENTIAL_NOT_ALLOWED',
          'This credential kind is not accepted here',
          403,
        );
      if (requiresMfa && !principal.session.mfa)
        throw iamHttpError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
      for (const rule of rules) await this.enforce(rule, found, principal, state);
      return true;
    } catch (error) {
      if (isIamError(error)) throw toHttpException(error);
      throw error;
    }
  }

  private async principal(
    request: RequestLike,
    key: object,
    anonymousAllowed: boolean,
  ): Promise<AuthenticatedPrincipal | null> {
    const cached = stateOf(key);
    if (cached?.principal) return cached.principal;
    const headers = headersOf(request);
    if (anonymousAllowed && !headers.has('authorization') && !headers.has('cookie')) return null;
    try {
      return await this.options.iam.authenticate(credentialOf(request));
    } catch (error) {
      if (anonymousAllowed && isAuthenticationError(error)) return null;
      throw error;
    }
  }

  /**
   * Cookie credentials ride along on cross-site form posts; bearer credentials never do. The scheme is matched
   * case-insensitively (RFC 9110), as the server's own credential parsing does, for opaque tokens and session JWTs.
   */
  private checkCsrf(request: RequestLike): void {
    if (this.options.csrf === false) return;
    const method = (request.method ?? 'GET').toUpperCase();
    if (safeMethods.has(method)) return;
    const headers = headersOf(request);
    if (/^bearer\s/i.test(headers.get('authorization') ?? '')) return;
    const site = headers.get('sec-fetch-site');
    if (site === 'same-origin') return;
    const origin = headers.get('origin');
    const trusted =
      typeof this.options.csrf === 'object' ? (this.options.csrf.trustedOrigins ?? []) : [];
    if (origin) {
      if (trusted.includes(origin)) return;
      try {
        if (new URL(origin).host === headers.get('host')) return;
      } catch {
        /* An unparsable Origin is rejected below. */
      }
    } else if (!site) return; // Non-browser clients send neither header and carry no ambient cookies.
    throw iamHttpError('CSRF_REJECTED', 'Cross-site request rejected', 403);
  }

  private async enforce(
    rule: AuthorizeRule,
    { request, args }: RequestScope,
    principal: AuthenticatedPrincipal,
    state: IamRequestState,
  ): Promise<void> {
    const tenantId = await resolveTenant(
      rule.tenant,
      this.options.tenant,
      request,
      principal,
      args,
    );
    const resource = await this.resource(rule, request, principal, tenantId, args);
    const decision = await this.options.iam.authorize({
      ...credentialOf(request),
      tenantId,
      action: rule.action,
      resource,
    });
    state.tenantId = tenantId;
    state.decisions.push({ action: rule.action, tenantId, resource, decision });
    if (!decision.allowed) throw iamHttpError('ACCESS_DENIED', 'Access denied', 403);
  }

  private async resource(
    rule: AuthorizeRule,
    request: RequestLike,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    args?: Record<string, unknown>,
  ): Promise<ResourceTarget> {
    const source = rule.resource;
    if (!source) return { type: 'iam', id: tenantId };
    if (typeof source === 'function') return source(request, principal);
    const id = await resolveValue(source.id, request, principal, args);
    if (!id) throw iamHttpError('INVALID_INPUT', `Missing ${source.type} identifier`, 400);
    return { type: source.type, id };
  }
}
