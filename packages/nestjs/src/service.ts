import { Inject, Injectable } from '@nestjs/common';
import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type Decision,
} from '@better-iam/core';
import { IAM_OPTIONS, credentialOf, isAuthenticationError } from './context.js';
import type { IamInstance, IamModuleOptions, RequestLike, ResourceTarget } from './types.js';

type Assertions = IamInstance['api']['assertions'];

/**
 * Request-scoped IAM calls for controllers and providers: every method takes the incoming request (Express, Fastify,
 * or anything with `headers`) and forwards its credential, so decisions are always made for the actual caller.
 */
@Injectable()
export class IamService {
  constructor(@Inject(IAM_OPTIONS) private readonly options: IamModuleOptions) {}

  /** The underlying `betterIam()` instance, for administrative calls with an explicit credential. */
  get iam(): IamInstance {
    return this.options.iam;
  }

  /** The request's credential, for direct administrative calls: `iam.api.identities.list(credential, input)`. */
  credential(request: RequestLike): CredentialInput {
    return credentialOf(request);
  }

  /**
   * Readiness of the IAM server's database through its `/health` endpoint, in process (no network hop): for
   * Terminus indicators or a readiness route. Needs a server that reports its `endpoint`.
   */
  async health(): Promise<{ status: 'up' | 'down'; latencyMs?: number }> {
    const endpoint = this.options.iam.endpoint;
    if (!endpoint) throw new Error('Better IAM: this server does not report its endpoint');
    try {
      const response = await this.options.iam.handler(
        new Request(`${endpoint.origin}${endpoint.basePath}/health`),
      );
      const body = (await response.json()) as { latencyMs?: number };
      return response.ok ? { status: 'up', latencyMs: body.latencyMs } : { status: 'down' };
    } catch {
      return { status: 'down' };
    }
  }

  /** The caller's principal, or null when the request carries no usable credential. */
  async principal(request: RequestLike): Promise<AuthenticatedPrincipal | null> {
    try {
      return await this.options.iam.authenticate(credentialOf(request));
    } catch (error) {
      if (isAuthenticationError(error)) return null;
      throw error;
    }
  }

  /** A recorded decision (denials and root overrides are audited); never throws for a denial. */
  authorize(
    request: RequestLike,
    input: { tenantId: string; action: string; resource: ResourceTarget },
  ): Promise<Decision> {
    return this.options.iam.authorize({ ...credentialOf(request), ...input });
  }

  /** Throws the server's `ACCESS_DENIED` error (403) unless the caller may perform the action. */
  async require(
    request: RequestLike,
    input: { tenantId: string; action: string; resource: ResourceTarget },
  ): Promise<void> {
    if (!(await this.authorize(request, input)).allowed)
      throw new IamError('ACCESS_DENIED', 'Access denied', 403);
  }

  /**
   * Advisory decisions for UI state keyed `${action}@${type}/${id}`; checks without a resource target the tenant.
   * Every key is false when the request is not authenticated.
   */
  async can(
    request: RequestLike,
    input: { tenantId: string; checks: { action: string; resource?: ResourceTarget }[] },
  ): Promise<Record<string, boolean>> {
    const checks = input.checks.map((check) => ({
      action: check.action,
      resource: check.resource ?? { type: 'iam', id: input.tenantId },
    }));
    const key = (check: { action: string; resource: ResourceTarget }) =>
      `${check.action}@${check.resource.type}/${check.resource.id}`;
    try {
      const { results } = await this.options.iam.authorizeMany({
        ...credentialOf(request),
        tenantId: input.tenantId,
        checks,
      });
      return Object.fromEntries(results.map((result) => [key(result), result.allowed]));
    } catch (error) {
      if (isAuthenticationError(error))
        return Object.fromEntries(checks.map((check) => [key(check), false]));
      throw error;
    }
  }

  /** Registered resources of a managed type the caller may act on, for list endpoints. */
  listAccessible(
    request: RequestLike,
    input: { tenantId: string; action: string; type: string; limit?: number; offset?: number },
  ): ReturnType<IamInstance['listAccessible']> {
    return this.options.iam.listAccessible({ ...credentialOf(request), ...input });
  }

  /** A short-lived signed assertion about the caller for a downstream service (`iam:assertions:create`). */
  assertion(
    request: RequestLike,
    input: Parameters<Assertions['issue']>[1],
  ): ReturnType<Assertions['issue']> {
    return this.options.iam.api.assertions.issue(credentialOf(request), input);
  }
}
