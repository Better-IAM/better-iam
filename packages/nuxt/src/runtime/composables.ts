// Auto-imported into Nuxt apps. Defined here so they resolve through this package's own dependencies and carry the
// session type of the instance the module registered.
import type { IamClient } from '@better-iam/client';
import { useIamClient as useClient, useSession, type UseSessionResult } from '@better-iam/vue';
import type { RegisteredIam } from '../h3.js';

export type RegisteredClient = IamClient<RegisteredIam>;
export type RegisteredSession = Awaited<ReturnType<RegisteredClient['auth']['getSession']>>;

export {
  useAccessible as useIamAccessible,
  useAuthorize as useIamAuthorize,
  useCan as useIamCan,
  IamCan,
} from '@better-iam/vue';

/** Reactive session state, typed from the app's IAM instance. */
export function useIamSession(): UseSessionResult<RegisteredSession> {
  return useSession<RegisteredClient>();
}

/** The typed browser client (the in-process session client during server rendering). */
export function useIamClient(): RegisteredClient {
  return useClient<RegisteredClient>();
}
