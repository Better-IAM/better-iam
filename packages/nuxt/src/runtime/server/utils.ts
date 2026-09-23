// Auto-imported into Nitro server routes, middleware, and plugins.
import type {
  AssertionInput,
  AssertionOf,
  H3EventLike,
  RegisteredIam,
  ResourceRef,
  SessionOf,
} from '../../h3.js';
import { iamH3, resolveIam } from './state.js';

/** The app's IAM instance (initialized), for calling `iam.api.*` directly with `{ headers: event.headers }`. */
export function useIam(): Promise<RegisteredIam> {
  return resolveIam();
}

/** The current session, or null when the request carries no usable credential. Memoized per request. */
export function getIamSession(event: H3EventLike): Promise<SessionOf<RegisteredIam> | null> {
  return iamH3.getSession(event);
}

/** The current session, or a 401 error. */
export function requireIamSession(event: H3EventLike): Promise<SessionOf<RegisteredIam>> {
  return iamH3.requireSession(event);
}

/** Enforces one action (default resource: the tenant); denial throws a 401/403/429 error carrying the IAM code. */
export function requireIamAccess(
  event: H3EventLike,
  input: { tenantId: string; action: string; resource?: ResourceRef },
): Promise<void> {
  return iamH3.require(event, input);
}

/** Advisory decisions keyed `${action}@${type}/${id}`, all false for anonymous requests. */
export function iamCan(
  event: H3EventLike,
  input: { tenantId: string; checks: { action: string; resource?: ResourceRef }[] },
): Promise<Record<string, boolean>> {
  return iamH3.can(event, input);
}

/** A short-lived signed assertion about the caller for a downstream service. */
export function issueIamAssertion(
  event: H3EventLike,
  input: AssertionInput,
): Promise<AssertionOf<RegisteredIam>> {
  return iamH3.assertion(event, input);
}

/** The credential for direct API calls: `iam.api.identities.list(iamCredential(event), …)`. */
export function iamCredential(event: H3EventLike): { headers: Headers } {
  return iamH3.credential(event) as { headers: Headers };
}
