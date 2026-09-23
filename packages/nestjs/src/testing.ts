import {
  IamError,
  matchPattern,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type Identity,
  type Session,
} from '@better-iam/core';
import type { IamInstance, ResourceTarget } from './types.js';

export interface TestingPrincipal {
  identity?: Partial<Identity>;
  session?: Partial<Session>;
}
export interface TestingCheck {
  principal: AuthenticatedPrincipal;
  tenantId: string;
  action: string;
  resource: ResourceTarget;
}
export interface TestingIamOptions {
  /** Principals by bearer token: `authorization: Bearer <token>` (or a `token` credential) selects one. */
  principals?: Record<string, TestingPrincipal>;
  /** Decides every authorization check, including `listAccessible` candidates (default: deny everything). */
  decide?(check: TestingCheck): boolean | Promise<boolean>;
  /** Registered resource ids per managed type, for `listAccessible` and `@FilterAccessible`. */
  resources?: Record<string, string[]>;
}
export type TestingIam = IamInstance & {
  /** Every decision made, in order, for assertions in tests. */
  readonly decisions: (TestingCheck & { allowed: boolean })[];
  /** The principal a token resolves to (defaults filled in). */
  principal(token: string): AuthenticatedPrincipal;
  /** Delivers an audit event to matching `@OnIamEvent` handlers, as `iam.events.dispatch()` would. */
  emit(event: Partial<AuditEvent> & { action: string }): Promise<void>;
};

/**
 * An in-memory stand-in for a `betterIam()` instance for unit and e2e tests of Nest applications: no database,
 * no password hashing, principals chosen by bearer token, and decisions made by a callback.
 *
 * ```ts
 * const iam = createTestingIam({
 *   principals: { alice: { identity: { email: 'alice@example.test' } } },
 *   decide: ({ principal, action }) => principal.identity.email === 'alice@example.test' && action === 'projects:read',
 * });
 * const moduleRef = await Test.createTestingModule({
 *   imports: [IamModule.forRoot({ iam, guard: true })],
 *   controllers: [ProjectsController],
 * }).compile();
 * ```
 */
export function createTestingIam(options: TestingIamOptions = {}): TestingIam {
  const decisions: (TestingCheck & { allowed: boolean })[] = [];
  const subscribers = new Set<{ patterns: string[]; handler: (event: AuditEvent) => unknown }>();
  const principal = (token: string): AuthenticatedPrincipal => {
    const spec = options.principals?.[token];
    if (!spec) throw new IamError('UNAUTHENTICATED', 'Unknown test credential', 401);
    const identity: Identity = {
      id: `identity_${token}`,
      tenantId: 'tenant_test',
      kind: 'user',
      name: token,
      status: 'active',
      emailVerified: true,
      rootAdmin: false,
      owner: false,
      createdAt: 0,
      ...spec.identity,
    };
    const session: Session = {
      id: `session_${token}`,
      tenantId: identity.tenantId,
      identityId: identity.id,
      tokenHash: '',
      createdAt: 0,
      expiresAt: Number.MAX_SAFE_INTEGER,
      lastSeenAt: 0,
      authenticatedAt: 0,
      mfa: false,
      kind: identity.kind === 'service' ? 'api-key' : 'user',
      ...spec.session,
    };
    return { identity, session };
  };
  const authenticate = async (input: CredentialInput): Promise<AuthenticatedPrincipal> => {
    const header = new Headers(input.headers).get('authorization');
    const token = input.token ?? (header?.startsWith('Bearer ') ? header.slice(7) : undefined);
    if (!token) throw new IamError('UNAUTHENTICATED', 'Authentication required', 401);
    return principal(token);
  };
  const decide = async (check: TestingCheck): Promise<boolean> => {
    const allowed = (await options.decide?.(check)) === true;
    decisions.push({ ...check, allowed });
    return allowed;
  };
  const unsupported = (name: string) => () => {
    throw new Error(`Better IAM testing: ${name} is not available in createTestingIam()`);
  };

  const stub = {
    decisions,
    principal,
    async emit(event: Partial<AuditEvent> & { action: string }) {
      const full: AuditEvent = {
        id: `event_${decisions.length}_${Date.now()}`,
        tenantId: 'tenant_test',
        actorId: 'identity_test',
        resourceId: '',
        timestamp: Date.now(),
        outcome: 'allow',
        ...event,
      } as AuditEvent;
      for (const subscriber of [...subscribers])
        if (subscriber.patterns.some((pattern) => matchPattern(pattern, full.action)))
          await subscriber.handler(full);
    },
    authenticate,
    async authorize(request: CredentialInput & Omit<TestingCheck, 'principal'>) {
      const current = await authenticate(request);
      const allowed = await decide({ principal: current, ...pick(request) });
      return { allowed, reason: allowed ? 'ALLOWED' : 'ACCESS_DENIED', matched: [] };
    },
    async authorizeMany(
      request: CredentialInput & {
        tenantId: string;
        checks: { action: string; resource: ResourceTarget }[];
      },
    ) {
      const current = await authenticate(request);
      const results = [];
      for (const check of request.checks) {
        const allowed = await decide({ principal: current, tenantId: request.tenantId, ...check });
        results.push({ ...check, allowed, reason: allowed ? 'ALLOWED' : 'ACCESS_DENIED' });
      }
      return { results };
    },
    async listAccessible(
      request: CredentialInput & {
        tenantId: string;
        action: string;
        type: string;
        limit?: number;
        offset?: number;
      },
    ) {
      const current = await authenticate(request);
      const accessible = [];
      for (const id of options.resources?.[request.type] ?? [])
        if (
          await decide({
            principal: current,
            tenantId: request.tenantId,
            action: request.action,
            resource: { type: request.type, id },
          })
        )
          accessible.push({
            id: `${request.type}/${id}`,
            tenantId: request.tenantId,
            type: request.type,
            resourceId: id,
            attributes: {},
            createdAt: 0,
            updatedAt: 0,
          });
      const offset = request.offset ?? 0;
      return {
        resources: accessible.slice(offset, offset + (request.limit ?? 100)),
        total: accessible.length,
      };
    },
    async handler() {
      return Response.json(
        { error: { code: 'NOT_FOUND', message: 'The testing IAM serves no HTTP API' } },
        { status: 404 },
      );
    },
    events: {
      subscribe(pattern: string | string[], handler: (event: AuditEvent) => unknown) {
        const subscriber = { patterns: Array.isArray(pattern) ? pattern : [pattern], handler };
        subscribers.add(subscriber);
        return () => {
          subscribers.delete(subscriber);
        };
      },
      async dispatch() {
        return { dispatched: 0 };
      },
    },
    api: { assertions: { issue: unsupported('assertions.issue') } },
  };
  return stub as unknown as TestingIam;
}

function pick(request: Omit<TestingCheck, 'principal'>): Omit<TestingCheck, 'principal'> {
  return { tenantId: request.tenantId, action: request.action, resource: request.resource };
}
