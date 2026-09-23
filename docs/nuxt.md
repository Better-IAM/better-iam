# Nuxt

`@better-iam/nuxt` is a Nuxt 3.14+/4 module. It mounts the IAM HTTP API in Nitro, installs the Vue bindings with the session loaded during server rendering, guards pages from `definePageMeta`, and auto-imports composables, the `<IamCan>` component, and server utilities. `@better-iam/vue` holds the framework-level Vue bindings and works without Nuxt. `@better-iam/nuxt/h3` holds the h3/Nitro server helpers and works without the module.

## Setup

```ts
// server/iam.ts: the instance, exported as `iam` or as the default export
import { betterIam } from 'better-iam';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';

export const iam = betterIam({
  database: sqliteAdapter({ filename: '.data/iam.db' }),
  secret: process.env.BETTER_IAM_SECRET!,
  baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
  permissions: { actions: ['projects:read', 'projects:manage'] },
  resolveResource: async (reference) => loadProjectOwnership(reference),
});
```

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ['@better-iam/nuxt'],
  betterIam: {
    instance: '~~/server/iam', // default
    loginPath: '/login',
  },
});
```

| Option        | Default         | Meaning                                                                      |
| ------------- | --------------- | ---------------------------------------------------------------------------- |
| `instance`    | `~~/server/iam` | File exporting the `betterIam()` result as `iam` or `default`                |
| `apiPath`     | `/api/iam`      | Where the handler is mounted; must equal the instance's `basePath`           |
| `handler`     | `true`          | Mount the IAM handler at `${apiPath}/**` (turn off to mount it yourself)     |
| `initialize`  | `true`          | Run `iam.initialize()` before first use (turn off when the CLI migrates)     |
| `loginPath`   | `/login`        | Where the route middleware sends signed-out visitors                         |
| `requireAuth` | `false`         | Every page needs a session unless it sets `iam: false`                       |
| `ssrSession`  | `true`          | Load the session while rendering on the server                               |
| `nextParam`   | `next`          | Query parameter carrying the original path to the login page (`''` omits it) |

`loginPath`, `requireAuth`, `ssrSession`, and `nextParam` live in `runtimeConfig.public.betterIam`, so `NUXT_PUBLIC_BETTER_IAM_LOGIN_PATH` and similar variables override them at runtime.

## Pages

```vue
<script setup lang="ts">
// A session is required; signed-out visitors go to /login?next=/projects/42.
definePageMeta({ iam: true });
</script>
```

```vue
<script setup lang="ts">
// A session plus an advisory decision. The tenant defaults to the session's; the resource to iam/{tenantId}.
definePageMeta({
  iam: {
    action: 'projects:manage',
    resource: (route) => ({ type: 'project', id: String(route.params.id) }),
    redirectTo: '/projects', // omit to render a 403 error page
  },
});
</script>
```

`iam: false` opts a page out when `requireAuth` is on. The middleware runs during server rendering, where a redirect becomes a 302 and a denial a 403 response, and during client navigation, where a denial renders the error page. It only decides what to render. Server routes and the IAM API still enforce every operation.

## Components and composables

```vue
<script setup lang="ts">
const { session, isAuthenticated, signOut } = useIamSession();
const { resources } = useIamAccessible(() => ({
  tenantId: session.value!.session.tenantId,
  action: 'projects:read',
  type: 'project',
}));
const { allowed } = useIamCan(() => ({
  tenantId: session.value!.session.tenantId,
  action: 'iam:identities:create',
}));
</script>

<template>
  <IamCan
    :tenant-id="session!.session.tenantId"
    action="projects:manage"
    :resource="{ type: 'project', id }"
  >
    <button>Manage</button>
    <template #fallback>Read only</template>
    <template #loading>…</template>
  </IamCan>
</template>
```

| Auto-import        | From `@better-iam/vue` | Notes                                                        |
| ------------------ | ---------------------- | ------------------------------------------------------------ |
| `useIamSession`    | `useSession`           | Typed from the registered instance: `session.identity.email` |
| `useIamClient`     | `useIamClient`         | The typed browser client (see below during SSR)              |
| `useIamAuthorize`  | `useAuthorize`         | Batched checks; `allowed(action, resource?)`                 |
| `useIamCan`        | `useCan`               | One decision as a `ComputedRef<boolean>`                     |
| `useIamAccessible` | `useAccessible`        | Reverse query for managed resource types                     |
| `<IamCan>`         | `IamCan`               | `default` / `fallback` / `loading` slots                     |

Inputs accept refs or getters and re-run when they change or when the signed-in identity changes. A session refresh for the same identity does not re-run them.

### Server rendering and hydration

During SSR the plugin does not call the HTTP API, which refuses cookie requests without an `Origin`. Instead a Nitro plugin binds an in-process session client to each request (`event.context.betterIam`). The session is read once per request and handed to the browser in the payload (`better-iam:session`). Decision and accessible-resource queries used by rendered components are awaited with `onServerPrefetch`, and their results travel in `better-iam:hydration`. The browser consumes each result once instead of refetching, so the first paint shows the right buttons with no hydration mismatch. After that, queries fetch normally. During SSR, `useIamClient()` returns the bound client (`auth.getSession`, `authorizeMany`, `listAccessible`); call other API methods from server routes.

### Signing in

The client signs in through the mounted API, and the HTTP handler sets the session cookie. Then tell the store:

```ts
const client = useIamClient();
const { setSession } = useIamSession();
const result = await client.auth.signIn({ tenantId, email, password });
if ('token' in result) setSession(await client.auth.getSession());
else await navigateTo('/login/mfa'); // result.challenge → client.auth.verifyMfa(...)
```

## Server routes

```ts
// server/api/projects/[id].delete.ts
export default defineEventHandler(async (event) => {
  const { session } = await requireIamSession(event); // 401 without a session
  const id = getRouterParam(event, 'id')!;
  await requireIamAccess(event, {
    tenantId: session.tenantId,
    action: 'projects:manage',
    resource: { type: 'project', id },
  }); // 401/403/429 with data.code = the IAM error code
  await deleteProject(id);
  return { ok: true };
});
```

| Server auto-import                    | Purpose                                                |
| ------------------------------------- | ------------------------------------------------------ |
| `getIamSession(event)`                | Session or `null`; memoized per request                |
| `requireIamSession(event)`            | Session or a 401 h3 error                              |
| `requireIamAccess(event, input)`      | Enforce one action (default resource `iam/{tenantId}`) |
| `iamCan(event, { tenantId, checks })` | Advisory decisions keyed `action@type/id`              |
| `issueIamAssertion(event, input)`     | Short-lived signed assertion for a downstream service  |
| `iamCredential(event)`                | `{ headers }` for direct `iam.api.*` calls             |
| `useIam()`                            | The initialized instance                               |

Errors are h3 errors with the IAM status. Their `statusMessage` and `data.code` carry the IAM code, so the JSON error body a client receives names it (`UNAUTHENTICATED`, `ACCESS_DENIED`, `RATE_LIMITED`, …).

## Without Nuxt

Any h3 v1/v2 or Nitro app can use the server helpers directly:

```ts
import { createApp, createError, defineEventHandler, toWebRequest } from 'h3';
import { createIamH3 } from '@better-iam/nuxt/h3';

const iamH3 = createIamH3(iam, { toRequest: toWebRequest, createError });
app.use(
  '/api/iam',
  defineEventHandler((event) => iamH3.handler(event)),
);
app.use(
  '/me',
  defineEventHandler(async (event) => (await iamH3.requireSession(event)).identity),
);
```

Without `toRequest`, the helper reads the request from h3 v2 `event.req`, h3 v1 `event.web.request`, or the Node request stream. Without `createError`, it throws `IamH3Error`, which h3 treats as one of its own errors.

Any Vue 3.3+ app can use the bindings directly: `app.use(createIam({ client: createIamClient<typeof iam>() }))`. For custom SSR, pass `server: true`, an in-process client, and `createHydration()` on the server. Serialize `hydration.state` into the page and pass `createHydration(state)` on the client.
