import { SetMetadata, createParamDecorator, type ExecutionContext } from '@nestjs/common';
import {
  AUTHORIZE_KEY,
  CREDENTIALS_KEY,
  EVENT_KEY,
  MFA_KEY,
  PUBLIC_KEY,
  stateFromContext,
} from './context.js';
import type {
  AuthorizeRule,
  CredentialKind,
  IamRequestState,
  ResourceSource,
  ValueSource,
} from './types.js';

/** Skips the session requirement; the guard still resolves a principal when a credential is present. */
export const Public = () => SetMetadata(PUBLIC_KEY, true);

/** Requires a session that completed multi-factor authentication (user sessions only). */
export const RequireMfa = () => SetMetadata(MFA_KEY, true);

/** Restricts which credential kinds may call the handler, e.g. `@Credentials('api-key')` for machine endpoints. */
export const Credentials = (...kinds: CredentialKind[]) => SetMetadata(CREDENTIALS_KEY, kinds);

/**
 * Enforces `action` before the handler runs. Rules accumulate: every `@Authorize` on the class and the method must
 * allow. The resource defaults to the tenant itself (`iam/{tenantId}`) and the tenant to the module's resolver.
 *
 * ```ts
 * @Authorize('projects:read', { resource: { type: 'project', id: { param: 'id' } } })
 * ```
 */
export function Authorize(
  action: string,
  options: { resource?: ResourceSource; tenant?: ValueSource } = {},
): ClassDecorator & MethodDecorator {
  const rule: AuthorizeRule = { action, ...options };
  return (target: object, _key?: string | symbol, descriptor?: PropertyDescriptor) => {
    const holder = descriptor ? (descriptor.value as object) : target;
    const existing =
      (Reflect.getMetadata(AUTHORIZE_KEY, holder) as AuthorizeRule[] | undefined) ?? [];
    Reflect.defineMetadata(AUTHORIZE_KEY, [...existing, rule], holder);
    return descriptor as never;
  };
}

function state(context: ExecutionContext): IamRequestState {
  const found = stateFromContext(context);
  if (!found)
    throw new Error(
      'Better IAM: IamGuard did not run for this handler; apply it with @UseGuards or `guard: true`',
    );
  return found;
}

/** The authenticated `{ identity, session }`, or null on a `@Public()` handler called without a credential. */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext) => state(context).principal,
);
/** The caller's identity, or null on a `@Public()` handler called without a credential. */
export const CurrentIdentity = createParamDecorator(
  (_data: unknown, context: ExecutionContext) => state(context).principal?.identity ?? null,
);
/** The caller's session record, or null on a `@Public()` handler called without a credential. */
export const CurrentSession = createParamDecorator(
  (_data: unknown, context: ExecutionContext) => state(context).principal?.session ?? null,
);
/** The tenant the request's `@Authorize` rules were evaluated in (or the session tenant when there were none). */
export const TenantId = createParamDecorator(
  (_data: unknown, context: ExecutionContext) => state(context).tenantId ?? null,
);

/**
 * Subscribes a provider method to audit events whose action matches the pattern(s), e.g. `identity:*`. Delivery is
 * post-commit and at-least-once, driven by `iam.events.dispatch()` (see `IamModule`'s `dispatchIntervalMs`).
 */
export const OnIamEvent = (pattern: string | string[]) => SetMetadata(EVENT_KEY, pattern);
