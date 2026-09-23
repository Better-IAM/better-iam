# @better-iam/svelte

SvelteKit and Svelte bindings for Better IAM.

- `@better-iam/svelte/kit` is the server side. A `handle` hook serves the IAM API, fills `event.locals.iam`, and enforces path rules. `guard` wraps server loads and `action` wraps form actions.
- `@better-iam/svelte` is the browser side: stores for the session and advisory decisions, for Svelte 4 and 5.

Full guide: [docs/sveltekit.md](../../docs/sveltekit.md). Runnable app: [examples/sveltekit](../../examples/sveltekit/README.md).

```ts
// src/hooks.server.ts
import { createIamKit } from '@better-iam/svelte/kit';
import { iam } from '$lib/server/iam';

export const iamKit = createIamKit(iam, {
  protect: [{ path: '/app' }, { path: '/admin', authorize: { action: 'iam:identities:read' } }],
});
export const handle = iamKit.handle;
```

```ts
// src/routes/projects/+page.server.ts
export const load = iamKit.guard(async (event, session) => ({
  canCreate: await event.locals.iam.can('projects:create'),
  name: session.identity.name,
}));
```

```svelte
<script>
  import { createIam } from '@better-iam/svelte';
  let { data } = $props();
  const iam = createIam({ client, initialSession: data.session });
  const { session } = iam;
  const canManage = iam.can({ tenantId: data.session?.session.tenantId ?? '', action: 'projects:manage' });
</script>

{#if $canManage.allowed}<button>Manage</button>{/if}
```

The stores and `can()` are advisory. The server enforces every operation.
