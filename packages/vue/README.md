# @better-iam/vue

Vue 3.3+ bindings for the Better IAM browser client: a plugin holding one session store, composables for the session and advisory authorization decisions, and an `IamCan` component, with server-rendering support. Everything here is advisory UI state; the server enforces every operation. Nuxt apps use [`@better-iam/nuxt`](../nuxt/README.md), which installs this for you.

```ts
import { createApp } from 'vue';
import { createIamClient } from '@better-iam/client';
import { createIam } from '@better-iam/vue';
import type { iam } from './server.js';

const client = createIamClient<typeof iam>({ baseURL: 'https://app.example.com' });
createApp(App).use(createIam({ client })).mount('#app');
```

```vue
<script setup lang="ts">
import { useAccessible, useAuthorize, useSession, IamCan } from '@better-iam/vue';
const props = defineProps<{ tenantId: string; projectId: string }>();
const { status, session, signOut } = useSession<typeof client>();
const { allowed } = useAuthorize(() => ({
  tenantId: props.tenantId,
  checks: [{ action: 'projects:manage', resource: { type: 'project', id: props.projectId } }],
}));
const { resources } = useAccessible(() => ({
  tenantId: props.tenantId,
  action: 'projects:read',
  type: 'project',
}));
</script>

<template>
  <p v-if="status === 'loading'">Loading…</p>
  <template v-else-if="session">
    {{ session.identity.name }} <button @click="signOut">Sign out</button>
    <button v-if="allowed('projects:manage', { type: 'project', id: projectId })">Manage</button>
    <IamCan :tenant-id="tenantId" action="iam:identities:create">
      <a href="/invite">Invite a member</a>
      <template #fallback>Ask an administrator to invite people.</template>
    </IamCan>
  </template>
</template>
```

- `createIam({ client, initialSession?, refreshOnFocus?, refreshIntervalMs?, hydration?, server? })` loads the session on install unless `initialSession` is given (`null` = known signed-out), refreshes on focus by default, and registers `IamCan` globally (`registerComponents: false` to skip).
- `useSession` returns computed `status`, `session`, `error`, `isAuthenticated` plus `refresh`, `signOut`, and `setSession` for applying a sign-in response.
- `useAuthorize`, `useCan`, and `useAccessible` take a ref or getter and re-run when it changes or the signed-in identity changes. A session refresh for the same identity does not re-run them.
- `useAgreements({ tenantId })` returns the person's terms of use, `pending` (required, not accepted in their current version), and `accept(agreement)`; `useAccessPaths({ tenantId, action, resource })` returns `allowed` and, when denied, the self-service `paths` (`mfa`, `accept-agreements`, `activate`, `request-package`) the server verified would allow the person. Both are prefetched during SSR like the others.
- `useTeams({ tenantId })` returns the person's teams (role, expiry, and the teams above each), their `pending` join requests, and the teams they may ask to join (`joinable`), with `requestToJoin(teamId, justification?)`, `cancelRequest(requestId)`, and `leave(teamId)`. See [teams and departments](../../docs/teams-and-departments.md).
- Server rendering: with `server: true` (detected when `window` is absent), queries in rendered components are awaited through `onServerPrefetch` and written to `hydration`. On the client, each hydrated result is used once instead of fetching, so markup matches. `createHydration(state?)` is a plain-object implementation to serialize.
- `createSessionStore` / `isUnauthenticated` come from `@better-iam/client/session`, shared with `@better-iam/react`.

License: MIT.
