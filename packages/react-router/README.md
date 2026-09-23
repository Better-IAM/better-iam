# @better-iam/react-router

React Router (framework mode, v7.9+ / v8) integration for Better IAM:

- `middleware` for the root route gives every loader and action per-request helpers and puts IAM cookies on the response
- `api` serves the IAM HTTP API from an `api/iam/*` resource route
- `guard` wraps loaders and `action` wraps actions, with login and step-up redirects, 403 `data()` for error boundaries, and refusals returned for `useActionData`

```ts
export const iamRouter = createIamRouter(iam, { loginPath: '/login' });
// app/root.tsx
export const middleware = [iamRouter.middleware];
// app/routes/admin.tsx
export const loader = iamRouter.guard(async (args, session) => ({ name: session.identity.name }), {
  authorize: { action: 'iam:identities:read' },
});
```

Guide: [docs/react-router.md](../../docs/react-router.md). Example: [examples/react-router](../../examples/react-router/README.md).
