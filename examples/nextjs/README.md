# Next.js example

A Next.js 15 App Router application built on `@better-iam/next`. It seeds an in-memory database on first request with an `acme` organization and three accounts:

| Account            | Password                  | Access                                      |
| ------------------ | ------------------------- | ------------------------------------------- |
| `reader@acme.test` | `example-reader-password` | `documents:read` through a Reader role      |
| `owner@acme.test`  | `example-owner-password`  | organization owner (full access)            |
| `guest@acme.test`  | `example-guest-password`  | no grants, so the document page answers 403 |

```bash
pnpm --filter @better-iam/example-nextjs dev
```

Open http://localhost:3300. Build the workspace first (`pnpm build`), because the example imports the packages' `dist` output.

| File                                | Shows                                                                                                                                                     |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `middleware.ts`                     | `createIamMiddleware` from `@better-iam/next/edge`: public globs, signed-in redirect, `?next=` forwarding                                                 |
| `lib/iam.ts`                        | the server instance (loaded at runtime, outside the bundle) and `createIamNext` with `interrupts: 'forbidden'`, `stepUpPath`, and `dispatchAfterResponse` |
| `app/login/actions.ts`              | `iamNext.authActions()`: the sign-in, step-up, password-reset, and sign-out server actions                                                                |
| `app/login/page.tsx`                | `<SignInForm>` with "keep me signed in" and emailed sign-in codes; works without client JavaScript                                                        |
| `app/reauth/page.tsx`               | the step-up page: `<ReauthenticateForm>`                                                                                                                  |
| `app/forgot`, `app/reset`           | `<PasswordResetRequestForm>` and `<PasswordResetForm>`                                                                                                    |
| `app/dev/inbox/page.tsx`            | development only: the captured emails (sign-in codes, reset links), delivered by `after()`                                                                |
| `app/providers.tsx`                 | `IamNextProvider` and a client-side sign-out that refreshes server components                                                                             |
| `app/[org]/layout.tsx`              | `requireTenantSession({ slug })`: unknown aliases 404, other organizations go to the login page                                                           |
| `app/[org]/page.tsx`                | `iamNext.page`, `can()` advisory decisions, and the server `<iamNext.Can>`                                                                                |
| `app/[org]/security/page.tsx`       | `stepUp: { maxAgeMs }`: after 15 seconds (`EXAMPLE_STEP_UP_MS`) the page sends you to `/reauth`                                                           |
| `app/[org]/documents/[id]/page.tsx` | `iamNext.page` with `authorize`; denials render `app/forbidden.tsx` through `forbidden()`                                                                 |
| `app/[org]/notes/*`                 | `iamNext.action` with `useActionState`: `ACCESS_DENIED` comes back to the form                                                                            |
| `app/api/documents/[id]/route.ts`   | `iamNext.route`: JSON with 401/403 envelopes                                                                                                              |
| `app/api/whoami/route.ts`           | `iamNext.apiRoute`: sessions, API keys, and assumed roles, with a sanitized principal                                                                     |
| `app/api/cron/route.ts`             | `iamNext.background.cron()`; call it with `Authorization: Bearer example-cron-secret` (set `CRON_SECRET` in real deployments)                             |
| `app/api/iam/[...path]/route.ts`    | `iamNext.handlers()` for the browser client and `/health`                                                                                                 |

The server packages resolve through workspace symlinks, which puts them outside `node_modules`, where `serverExternalPackages` does not apply. `lib/iam.ts` therefore loads them with `import(/* webpackIgnore: true */ ...)`, so the native `argon2` and `better-sqlite3` modules are never bundled. An application that installs Better IAM from a registry can list the packages in `serverExternalPackages` instead.
