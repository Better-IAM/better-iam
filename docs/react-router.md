# React Router

`@better-iam/react-router` (umbrella: `better-iam/react-router`) integrates Better IAM with React Router framework mode, v7.9+ and v8. It uses route middleware and the router context:

- a root middleware creates the per-request helpers and adds the cookies the in-process client receives to the response
- a resource route serves the IAM HTTP API
- `guard` wraps loaders and `action` wraps actions

It is built on [`@better-iam/middleware`](node-frameworks.md), so the helpers are the same as `req.iam` in Express. Browser components use [`@better-iam/react`](../packages/react/README.md) (`IamProvider`, `useSession`, `useAuthorize`, `Can`). [`examples/react-router`](../examples/react-router/README.md) is a complete app with a smoke test.

## Setup

```ts
// app/iam.server.ts
import { betterIam } from 'better-iam';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';
import { createIamRouter } from 'better-iam/react-router';

export const iam = betterIam({
  /* database, secret, baseURL, permissions, resolveResource */
});
export const iamRouter = createIamRouter(iam, { loginPath: '/login', stepUpPath: '/verify' });
export const ready = iam.initialize();
```

```tsx
// app/root.tsx
import { createIamClient, type IamClient } from 'better-iam/client';
import { IamProvider } from 'better-iam/react';
import type { Route } from './+types/root';
import { iamRouter, ready, type iam } from './iam.server';

export const middleware: Route.MiddlewareFunction[] = [
  async (_args, next) => {
    await ready;
    return next();
  },
  iamRouter.middleware,
];
export async function loader(args: Route.LoaderArgs) {
  return { ...(await iamRouter.sessionData(args)), origin: new URL(args.request.url).origin };
}
export default function App({ loaderData }: Route.ComponentProps) {
  const [client] = useState(() => createIamClient<typeof iam>({ baseURL: loaderData.origin }));
  return (
    <IamProvider client={client} initialSession={loaderData.session}>
      <Outlet />
    </IamProvider>
  );
}
```

```ts
// app/routes.ts: route('api/iam/*', 'routes/api.iam.ts')
// app/routes/api.iam.ts
export const loader = iamRouter.api;
export const action = iamRouter.api;
```

Form actions revalidate the root loader, so after a sign-in or sign-out, push the new `loaderData.session` into the store with `useSession().setSession` in an effect (the example's `Header` does this).

## Loaders and actions

```ts
// app/routes/projects.$id.tsx
export const loader = iamRouter.guard(
  async (args: Route.LoaderArgs, session) => ({
    project: await loadProject(args.params.id),
    canManage: await iamRouter
      .helpers(args)
      .can('projects:manage', { type: 'project', id: args.params.id }),
  }),
  {
    authorize: {
      action: 'projects:read',
      resource: (args) => ({ type: 'project', id: args.params.id }),
    },
  },
);

export const action = iamRouter.action(
  async (args: Route.ActionArgs, session) =>
    renameProject(args.params.id, await args.request.formData()),
  {
    authorize: {
      action: 'projects:manage',
      resource: (args) => ({ type: 'project', id: args.params.id }),
    },
  },
);
```

- **`guard(loader, { stepUp?, authorize?, loginRedirect?, deniedRedirect? })`**
  - Signed-out visitors are redirected to `loginPath?next=…`. Document and `.data` requests both work, and `next` never includes `.data`.
  - Sessions that must step up are redirected to `stepUpPath?next=…&reason=…`.
  - A denial throws `data({ code, message }, { status: 403 })` for the route's `ErrorBoundary` (`isRouteErrorResponse(error)`, `error.data.code`), or redirects to `deniedRedirect`.
- **`action(fn, { stepUp?, authorize? })`**
  - First refuses cookie-authenticated requests from untrusted origins (`UNTRUSTED_ORIGIN`, or `CSRF_REJECTED` without an `Origin`).
  - Returns every IAM refusal as `data({ code, message }, { status })` for `useActionData`: 401, 403, 400 for invalid input, 429 when rate limited. Redirects and other errors propagate.
  - React Router v8 also refuses cross-origin document action posts on its own (400), so the origin check is a second layer that also covers `.data` requests.
- **`helpers(args)`** returns the per-request helpers: `getSession`, `requireSession`, `require`, a batched `can`, `authorize`, `listAccessible`, `assertion`, `credential()` for direct `iam.api.*` calls, `signOut`, and `client`. `client` calls the IAM handler in process, so `helpers(args).client.auth.signIn(...)` in an action followed by `throw redirect(next)` signs the person in with no browser JavaScript. The middleware puts the session cookie on the redirect.
- **`requireSession(args, { stepUp? })`** and **`require(args, action, resource?, { deniedRedirect? })`** are the same checks for hand-written loaders.

Options: `loginPath` (default `/login`), `stepUpPath`, `basePath`, `trustedOrigins`, `csrf` (default `true`).

## Build notes

- **Native modules.** Keep the server packages out of the SSR bundle with `ssr: { external: ['better-iam'] }` (or `@better-iam/server` plus the adapter). In a monorepo, also add `resolve: { dedupe: ['react-router', 'react', 'react-dom'] }` so the app and the integration share one React Router.
- **Server-only code.** Keep `iam.server.ts` server-only; the example's client bundle contains no server code.
