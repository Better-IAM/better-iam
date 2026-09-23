# React Router example

A React Router v8 framework-mode app (SSR, `react-router-serve`) using `@better-iam/react-router` and `@better-iam/react`. The pieces:

- `app/iam.server.ts` holds the instance, `createIamRouter`, and the demo seed.
- `app/root.tsx` has the middleware, the session loader, `IamProvider`, and an error boundary that shows IAM refusal codes.
- `routes/api.iam.ts` is the IAM API resource route.
- The login and logout actions use the in-process client (no JavaScript needed).
- `/account` is a guarded loader with a guarded action that returns `ACCESS_DENIED` for plain members.
- `/admin` is a guarded loader, 403 for plain members.
- `/api/me` uses the helpers.

With `DEMO_SEED=1` the server seeds a fresh database with a member: `member@example.test` / `demo member password for react router`. It discards the root authenticator secret, so it is for demos only.

```bash
pnpm --filter @better-iam/example-react-router build
```

```bash
pnpm --filter @better-iam/example-react-router smoke
```

The smoke test starts the production build on a free port with a temporary database. It checks:

- signed-out redirects (`/account` → `/login?next=%2Faccount`), for documents and `.data` requests
- a failed sign-in, then sign-in through the action with the cookie on the redirect
- the server-rendered session and decision
- the guarded action's `ACCESS_DENIED` and a refused cross-site post
- the 403 error boundary on `/admin`
- `/api/me`, the IAM API route, and sign-out clearing the cookie and ending the session

`pnpm --filter @better-iam/example-react-router typecheck` runs typegen and `tsc`.
