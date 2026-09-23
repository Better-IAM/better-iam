import { defineNuxtPlugin, useRequestEvent, useRuntimeConfig, useState } from 'nuxt/app';
import { createIamClient } from '@better-iam/client';
import { isUnauthenticated } from '@better-iam/client/session';
import { createHydration, createIam, type SessionClient } from '@better-iam/vue';
import type { RegisteredIam } from '../h3.js';
import { defaultPublicConfig, type IamPublicConfig } from './config.js';

/**
 * Installs the Vue bindings. On the server the client is the in-process session client the Nitro plugin attaches to
 * `event.context.betterIam`, so rendering never makes an HTTP round trip; in the browser it is the typed HTTP client.
 */
export default defineNuxtPlugin({
  name: 'better-iam',
  enforce: 'pre',
  async setup(nuxtApp) {
    const config: IamPublicConfig = {
      ...defaultPublicConfig,
      ...(useRuntimeConfig().public.betterIam as Partial<IamPublicConfig> | undefined),
    };
    const server = typeof window === 'undefined';
    const initial = useState<unknown>('better-iam:session', () => undefined);
    const hydration = useState<Record<string, unknown>>('better-iam:hydration', () => ({}));
    let client: SessionClient;
    if (server) {
      const bound = (useRequestEvent()?.context as { betterIam?: SessionClient } | undefined)
        ?.betterIam;
      if (!bound)
        throw new Error(
          'Better IAM: the Nitro plugin did not bind a session client to the request',
        );
      client = bound;
      if (config.ssrSession && initial.value === undefined) {
        try {
          initial.value = await bound.auth.getSession();
        } catch (error) {
          if (!isUnauthenticated(error)) throw error;
          initial.value = null;
        }
      }
    } else {
      client = createIamClient<RegisteredIam>({ basePath: config.apiPath });
    }
    const iam = createIam({
      client,
      ...(initial.value === undefined ? {} : { initialSession: initial.value }),
      hydration: createHydration(hydration.value),
      registerComponents: false,
      server,
    });
    nuxtApp.vueApp.use(iam);
    return { provide: { iam } };
  },
});
