# @better-iam/nuxt

Better IAM for Nuxt 3.14+ and 4. The module mounts the IAM API in Nitro and renders the session on the server, where advisory decisions are also resolved and then hydrated. It guards pages with `definePageMeta({ iam })` and auto-imports composables, `<IamCan>`, and server utilities. See the [Nuxt guide](../../docs/nuxt.md).

```ts
// nuxt.config.ts: server/iam.ts exports the betterIam() instance as `iam`
export default defineNuxtConfig({
  modules: ['@better-iam/nuxt'],
  betterIam: { instance: '~~/server/iam', loginPath: '/login' },
});
```

```vue
<script setup lang="ts">
definePageMeta({ iam: { action: 'projects:manage' } }); // or `true` for any session, `false` to opt out
const { session } = useIamSession();
</script>

<template>
  <IamCan :tenant-id="session!.session.tenantId" action="iam:identities:create">
    <NuxtLink to="/invite">Invite</NuxtLink>
  </IamCan>
</template>
```

```ts
// server/api/me.get.ts
export default defineEventHandler(async (event) => {
  const { identity, session } = await requireIamSession(event);
  await requireIamAccess(event, { tenantId: session.tenantId, action: 'projects:read' });
  return identity;
});
```

- App auto-imports: `useIamSession`, `useIamClient`, `useIamAuthorize`, `useIamCan`, `useIamAccessible`, and `<IamCan>`. Sessions are typed from the registered instance.
- Server auto-imports: `getIamSession`, `requireIamSession`, `requireIamAccess`, `iamCan`, `issueIamAssertion`, `iamCredential`, and `useIam`.
- `@better-iam/nuxt/h3` exports `createIamH3` for h3 v1/v2 and Nitro apps without the module.

License: Apache-2.0.
