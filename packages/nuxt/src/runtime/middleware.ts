import {
  abortNavigation,
  createError,
  defineNuxtRouteMiddleware,
  navigateTo,
  useNuxtApp,
  useRuntimeConfig,
} from 'nuxt/app';
import type { AuthorizationClient, Iam, SessionClient } from '@better-iam/vue';
import {
  defaultPublicConfig,
  type IamPageMeta,
  type IamPublicConfig,
  type IamRouteLike,
} from './config.js';

function sessionTenant(session: unknown): string | undefined {
  const tenantId = (session as { session?: { tenantId?: unknown } } | null)?.session?.tenantId;
  return typeof tenantId === 'string' ? tenantId : undefined;
}

/**
 * Global route middleware: pages declare `definePageMeta({ iam: true })` for a session or
 * `{ iam: { action, resource } }` for an advisory decision; with `requireAuth` every page needs a session unless it
 * opts out with `iam: false`. It runs during server rendering and client navigation alike.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const config: IamPublicConfig = {
    ...defaultPublicConfig,
    ...(useRuntimeConfig().public.betterIam as Partial<IamPublicConfig> | undefined),
  };
  const meta = to.meta.iam as IamPageMeta | undefined;
  const loginPage = to.path === config.loginPath || to.path.startsWith(`${config.loginPath}/`);
  const needed = meta === undefined ? config.requireAuth && !loginPage : meta !== false;
  if (!needed) return;
  const iam = useNuxtApp().$iam as Iam<SessionClient>;
  let snapshot = iam.store.getSnapshot();
  if (snapshot.status === 'loading') snapshot = await iam.store.refresh();
  if (snapshot.status !== 'authenticated') {
    if (loginPage) return;
    return navigateTo(
      config.nextParam
        ? { path: config.loginPath, query: { [config.nextParam]: to.fullPath } }
        : config.loginPath,
    );
  }
  if (typeof meta !== 'object') return;
  const route = to as unknown as IamRouteLike;
  const tenantId =
    typeof meta.tenantId === 'function'
      ? meta.tenantId(route, snapshot.session)
      : (meta.tenantId ?? sessionTenant(snapshot.session));
  if (!tenantId)
    throw new Error('Better IAM: page meta needs a tenantId the session cannot supply');
  const resource =
    typeof meta.resource === 'function'
      ? meta.resource(route)
      : (meta.resource ?? { type: 'iam', id: tenantId });
  const client = iam.client as AuthorizationClient;
  if (!client.authorizeMany)
    throw new Error('Better IAM: the client does not provide authorizeMany');
  const { results } = await client.authorizeMany({
    tenantId,
    checks: [{ action: meta.action, resource }],
  });
  if (results[0]?.allowed) return;
  if (meta.redirectTo) return navigateTo(meta.redirectTo);
  // Fatal, so client-side navigations render the error page too instead of silently staying put.
  return abortNavigation(
    createError({
      statusCode: 403,
      statusMessage: 'ACCESS_DENIED',
      message: `Not allowed to ${meta.action} ${resource.type}/${resource.id}`,
      fatal: true,
    }),
  );
});
