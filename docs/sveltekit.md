# SvelteKit

`@better-iam/svelte` has two entry points:

- `@better-iam/svelte/kit` is the server side. A `handle` hook serves the IAM HTTP API, attaches per-request helpers to `event.locals.iam`, and enforces path rules. `guard` wraps server loads and `action` wraps form actions.
- `@better-iam/svelte` is the browser side. It gives you Svelte stores for the session and advisory decisions, and works in Svelte 4 and 5 (runes or not). Server loads can hand their results to the stores, so the first render needs no extra requests.

The umbrella package exposes them as `better-iam/svelte/kit` and `better-iam/svelte`. [`examples/sveltekit`](../examples/sveltekit/README.md) is a complete app with a smoke test.

## Setup

```ts
// src/lib/server/iam.ts
import { betterIam } from 'better-iam';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';
import { createIamKit } from 'better-iam/svelte/kit';

export const iam = betterIam({
  database: sqliteAdapter({ filename: '.data/iam.db' }),
  secret: process.env.BETTER_IAM_SECRET!,
  baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:5173',
  permissions: { actions: ['projects:read', 'projects:manage'] },
  resolveResource: async (reference) => loadProjectOwnership(reference),
});

export const iamKit = createIamKit(iam, {
  protect: [
    { path: '/app' }, // any session
    { path: '/admin', authorize: { action: 'iam:identities:read' } },
    { path: '/billing', stepUp: { mfa: true } },
  ],
  stepUpPath: '/verify',
});
```

```ts
// src/hooks.server.ts
import { iam, iamKit } from '$lib/server/iam';

export const init = () => iam.initialize();
export const handle = iamKit.handle; // or sequence(iamKit.handle, yourHandle)
```

```ts
// src/app.d.ts
import type { IamLocals } from 'better-iam/svelte/kit';
import type { iam } from '$lib/server/iam';

declare global {
  namespace App {
    interface Locals {
      iam: IamLocals<typeof iam>;
    }
    interface Error {
      message: string;
      code?: string; // IAM refusals carry their code
    }
  }
}
export {};
```

| Option       | Default                                | Meaning                                                                                     |
| ------------ | -------------------------------------- | ------------------------------------------------------------------------------------------- |
| `basePath`   | the instance's `basePath`, `/api/iam`  | Where `handle` serves the IAM HTTP API                                                      |
| `serveApi`   | `true`                                 | Serve the API from `handle` (turn off when a `+server.ts` mounts `iam.handler`)             |
| `loginPath`  | `/login`                               | Where signed-out visitors go; `?next=` carries the path and query they wanted               |
| `stepUpPath` | none (the failure is a 403 error page) | Where sessions that must step up go, with `?next=` and `?reason=mfa\|recent\|impersonation` |
| `protect`    | `[]`                                   | Path rules `handle` enforces before any load, action, or endpoint runs                      |
| `localsKey`  | `iam`                                  | The `event.locals` property                                                                 |

A `protect` rule's `path` can be a prefix (`/admin` covers `/admin/users`, not `/administrator`), a regular expression, or a `(url) => boolean`. `authorize` takes `{ action, resource?, tenantId? }`; the resource defaults to the tenant (`iam/{tenantId}`) and the tenant to the session's. With `deniedRedirect` a refused visitor is redirected instead of shown a 403.

**Pages without a server load.** SvelteKit renders a page that has no `+page.server.ts` / `+layout.server.ts` load entirely in the browser during client-side navigation, so the request never reaches `handle`. Give every protected section a server load, which is where its data comes from anyway (`iamKit.guard` is a good fit). Full page loads, data requests (`__data.json`), form actions, and `+server.ts` endpoints always pass through `handle`, and redirects thrown there reach client-side navigations as SvelteKit redirects.

## Server loads, actions, and endpoints

`event.locals.iam` is created once per request. Sessions and decisions are memoized, and checks made in the same tick share one `authorizeMany` call.

| Member                                                       | Returns / does                                                                            |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `getSession()`                                               | The session, or `null`                                                                    |
| `requireSession({ stepUp?, loginRedirect?, returnTo? })`     | The session, or a 303 to the login / step-up page                                         |
| `require(action, resource?, { tenantId?, deniedRedirect? })` | Signed out → login redirect; denied → `deniedRedirect` or `error(403, { code })`          |
| `can(action, resource?, { tenantId? })`                      | An advisory boolean (false when signed out)                                               |
| `authorize(checks, { tenantId? })`                           | `{ action, resource, allowed, reason }[]`, the shape the browser stores take as `initial` |
| `listAccessible({ action, type, ... })`                      | The managed resources the caller may act on                                               |
| `assertion({ tenantId, audience, ... })`                     | A signed assertion for a downstream service                                               |
| `client`                                                     | A typed client calling `iam.handler` in process; `Set-Cookie` lands in `event.cookies`    |
| `credential()`                                               | `{ headers }` for direct `iam.api.*` calls, including cookies set earlier in the request  |
| `signOut()`                                                  | Ends the session and clears the cookie                                                    |

```ts
// src/routes/projects/[id]/+page.server.ts
import { iam, iamKit } from '$lib/server/iam';

export const load = iamKit.guard(
  async (event, session) => ({
    project: await loadProject(event.params.id),
    canManage: await event.locals.iam.can('projects:manage', {
      type: 'project',
      id: event.params.id,
    }),
  }),
  {
    authorize: {
      action: 'projects:read',
      resource: ({ event }) => ({ type: 'project', id: event.params.id }),
    },
  },
);

export const actions = {
  // IAM refusals come back as fail(status, { code, message }); redirects and other errors propagate.
  rename: iamKit.action(
    async (event, session) => {
      const name = String((await event.request.formData()).get('name'));
      return { project: await renameProject(event.params.id, name) };
    },
    {
      authorize: {
        action: 'projects:manage',
        resource: ({ event }) => ({ type: 'project', id: event.params.id }),
      },
    },
  ),
};
```

`guard(load, spec)` requires a session, then optional `stepUp` and `authorize`, then calls `load(event, session)`. Signed-out visitors are redirected to `loginRedirect ?? loginPath`, and denials become a 403 (or `deniedRedirect`). `action(fn, spec)` runs the same checks, but reports every IAM refusal as `fail()`: 401 `UNAUTHENTICATED`, 403 `MFA_REQUIRED` / `ACCESS_DENIED`, 400 for invalid input, 429 when rate limited. A `form` prop can then show `form.code`.

### Sign-in forms

The in-process client makes a no-JavaScript sign-in form a few lines long:

```ts
// src/routes/login/+page.server.ts
import { fail, redirect } from '@sveltejs/kit';
import { safeRedirectPath } from 'better-iam/svelte/kit';

export const actions = {
  default: async ({ request, locals, url }) => {
    const form = await request.formData();
    let result;
    try {
      result = await locals.iam.client.auth.signIn({
        tenantId: String(form.get('tenantId')),
        email: String(form.get('email')),
        password: String(form.get('password')),
      });
    } catch (error) {
      return fail(400, { message: (error as Error).message });
    }
    // Outside the try: redirect() throws, and a catch would swallow it.
    if ('mfaRequired' in result) redirect(303, `/verify?challenge=${result.challenge}`);
    redirect(303, safeRedirectPath(url.searchParams.get('next')));
  },
};
```

`safeRedirectPath` accepts only same-site paths and falls back to `/` for anything else (`//host`, schemes, backslashes, control characters). The helpers check step-up with `checkStepUp(session, requirement)`, which is exported for your own use and follows the server's rules. Impersonated sessions never satisfy a recency requirement, and `mfa: 'fresh'` refuses remembered devices, assumed roles, and API keys.

## Browser stores

```ts
// src/routes/+layout.server.ts
import { iamKit } from '$lib/server/iam';

export const load = async (event) => ({
  ...(await iamKit.sessionData(event)), // { session }
  permissions: await event.locals.iam.authorize([{ action: 'projects:create' }]),
  origin: event.url.origin,
});
```

```svelte
<!-- src/routes/+layout.svelte -->
<script lang="ts">
  import { createIamClient } from 'better-iam/client';
  import { createIam, setIamContext } from 'better-iam/svelte';
  import type { iam as server } from '$lib/server/iam';

  let { data, children } = $props();
  const iam = setIamContext(
    createIam({
      client: createIamClient<typeof server>({ baseURL: data.origin }),
      initialSession: data.session,
    }),
  );
  const { session } = iam;
  // Form actions re-run this load; keep the store on the server's answer.
  $effect(() => iam.setSession(data.session));
</script>

{#if $session.session}Signed in as {$session.session.identity.email}{/if}
{@render children()}
```

```svelte
<!-- any component -->
<script lang="ts">
  import { toStore } from 'svelte/store';
  import { getIamContext } from 'better-iam/svelte';

  let { data, projectId } = $props();
  const iam = getIamContext();
  const canManage = iam.can(
    toStore(() => ({
      tenantId: data.session?.session.tenantId ?? '',
      action: 'projects:manage',
      resource: { type: 'project', id: projectId },
    })),
  );
</script>

{#if $canManage.allowed}<button>Manage</button>{/if}
```

| Store                                 | Value                                                                                 |
| ------------------------------------- | ------------------------------------------------------------------------------------- |
| `iam.session`                         | `{ status, session, error }` (`loading`, `authenticated`, `unauthenticated`, `error`) |
| `iam.authorize(input, { initial? })`  | `{ status, results, error, allowed(action, resource?) }`                              |
| `iam.can(input, { initial? })`        | `{ status, allowed }`                                                                 |
| `iam.accessible(input, { initial? })` | `{ status, resources, total, error }`                                                 |

Inputs can be plain objects or stores (use `toStore(() => ...)` with runes). A query fetches only while subscribed. It refetches when its input or the signed-in identity changes, but not when a session refresh returns the same identity. Signing out resolves every check to denied (`reason: 'UNAUTHENTICATED'`). `initial` seeds a query with a server load's answer, and that answer is used instead of the first fetch. Each store has `refresh()`. `createIam` reloads the session when the tab regains focus (`refreshOnFocus: false` turns it off). It never fetches while server rendering. On Svelte 4, create the stores in a component and pass values the same way.

The stores only decide what to render. The server still enforces every operation.

## Deployment notes

- **Native modules.** Keep `better-iam` (or `@better-iam/server` and the adapter) out of the server bundle, e.g. `ssr: { external: ['better-iam'] }` in `vite.config`. `adapter-node` already leaves `dependencies` external.
- **One SvelteKit copy.** `redirect()` and `error()` are recognised by class. In a monorepo where the app and `@better-iam/svelte` could resolve different `@sveltejs/kit` copies, add `resolve: { dedupe: ['@sveltejs/kit', 'svelte'] }`.
- **Build-time imports.** `vite build` imports server modules to analyse routes. Guard environment checks with `building` from `$app/environment` (the example uses a placeholder secret and `:memory:` while building).
- **Cookies.** The helpers pass the IAM server's cookie attributes straight to `event.cookies.set`, including an explicit `secure` flag, so SvelteKit's localhost default doesn't change them. A stale cookie is harmless: `getSession()` returns `null`, and `signOut()` clears it.
