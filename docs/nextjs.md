# Next.js

`@better-iam/next` (also `better-iam/next`) integrates Better IAM with the Next.js 15 App Router. The package README has the API tour; this guide covers how the pieces fit, what each one guarantees, and complete flows.

## Layout of an application

```
lib/iam.ts                      betterIam({ ... })             Node runtime only (database, argon2)
lib/iam-next.ts                 createIamNext(iam, options)    server components, actions, route handlers
app/api/iam/[...path]/route.ts  iamNext.handlers()             browser client, OAuth/SAML/SCIM mounts, /health
middleware.ts                   createIamMiddleware(...)       edge: cookie presence + path forwarding
app/api/webhooks/iam/route.ts   createWebhookHandler(...)      optional: consume your own IAM events
```

Import middleware helpers from `@better-iam/next/edge`. That entry has no Node, React, or database imports, so the edge bundle stays small. The main entry re-exports everything in it.

If webpack must not bundle the server library (native `argon2` / `better-sqlite3`), load `lib/iam.ts` lazily and pass a factory: `createIamNext(() => getIam())`. The console app does this with `import(/* webpackIgnore: true */ 'better-iam')`.

## Reading the session

`iamNext.getSession()` reads the request's cookies (through `headers()` and `cookies()`) and returns `{ identity, session }` or `null`. It returns `null` for missing, expired, revoked, step-up-required, and inactive-tenant credentials. Any other failure is rethrown.

- **Per-request memoization.** The no-argument call goes through React `cache`, so a layout, its page, and nested server components share one lookup per render. Calls that pass `headers` explicitly are not memoized. Pass `cache` to replace React's (or `(fn) => fn` to disable it).
- **After a server action.** The helper merges `cookies()` into the headers it sends. Cookies a server action just set, such as a new session after sign-in, therefore apply to the re-render Next performs in the same response.
- **Client components.** `sessionForClient()` returns the session as plain JSON for `<IamProvider initialSession>`, so the first client render needs no fetch.

## Guards

| Helper                                   | Signed out                                          | Step-up missing                                                                 | Denied                                                | Other IAM errors             |
| ---------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------- |
| `requireSession()` / `page()`            | redirect to `loginPath?next=` (or `unauthorized()`) | redirect to `stepUpPath?next=&reason=`                                          | `authorize.redirectTo`, else throw (or `forbidden()`) | thrown                       |
| `require({ ..., redirectTo })`           | `redirectTo`, else throw (or `unauthorized()`)      | not applicable                                                                  | `redirectTo`, else throw (or `forbidden()`)           | thrown                       |
| `route()` / `apiRoute()` / `pages.api()` | `401` JSON envelope                                 | `403` with `MFA_REQUIRED` / `RECENT_AUTH_REQUIRED` / `IMPERSONATION_RESTRICTED` | `403` JSON envelope                                   | JSON envelope, server status |
| `action(fn, spec)`                       | `{ ok: false, error: { code: 'UNAUTHENTICATED' } }` | `{ ok: false, error: { code: 'RECENT_AUTH_REQUIRED', ... } }`                   | `{ ok: false, error: { code: 'ACCESS_DENIED' } }`     | `{ ok: false, error }`       |

"(or ...)" applies with `interrupts: true`, which uses Next's `unauthorized()` and `forbidden()` (enable `experimental.authInterrupts` and add `unauthorized.tsx` / `forbidden.tsx`). Without that option those calls throw an error in Next 15. `interrupts: 'forbidden'` interrupts denials only, so signed-out visitors are still redirected to the login page. This is the usual choice, and the example app uses it. Route handlers and server actions never redirect or interrupt; they always report through their response.

`authorize` takes `{ action, resource?, tenantId? }`. `resource` and `tenantId` are functions of the params (pages and routes) or of the arguments (actions). They default to the tenant itself (`iam/{tenantId}`) and the session's tenant. Decisions come from `iam.require`, so policies, boundaries, conditions, relationships, and audit behave exactly as they do elsewhere.

`route()` authenticates the request it receives with a session cookie or a bearer session token. `apiRoute()` also accepts API keys and assumed-role sessions (see Service credentials below). Only `IamError` and `IamClientError` become responses or `ActionResult`s. Other errors, even ones with a `code` field such as `ENOENT`, and Next control flow (`redirect()`, `notFound()`) propagate unchanged in every wrapper, so internal messages never reach a client.

Cookie-authenticated mutations to `route()`, `apiRoute()`, and `pages.api()` must come from this application (a matching `Origin`, or `Sec-Fetch-Site: same-origin`), the IAM origin, or an origin listed in `trustedOrigins`. That covers methods other than GET, HEAD, and OPTIONS that carry the session cookie and no `Authorization` header. Anything else is refused with `CSRF_REJECTED` or `UNTRUSTED_ORIGIN` (403) before the handler runs, the same boundary the IAM handler draws. Server actions are exempt because Next checks their origin itself.

`can()`, `allowed()`, and `<iamNext.Can>` are advisory: use them to decide what to render, and enforce the mutation itself with `action()`, `route()`, or the API. `allowed()` and `<iamNext.Can>` batch per request. Checks made while a render is in flight wait for one macrotask and then go out as a single deduplicated `authorizeMany` (50 checks per call, one call per tenant), so a page full of permission-dependent buttons costs one round trip. Answers are reused for the rest of the render.

## Server actions and the in-process client

`iamNext.client()` returns `createIamClient<typeof iam>` whose transport is `iam.handler` in the same process. For each call it:

1. copies the caller's `cookie`, `authorization`, `user-agent`, `accept-language`, and forwarding headers (`x-forwarded-*`, `x-real-ip`);
2. sets `Origin` to the IAM origin (`iam.endpoint.origin`, from `baseURL`) and sends JSON with `X-Better-IAM: 1`, which satisfies the server's CSRF boundary;
3. writes every `Set-Cookie` the handler returns (session, trusted device, sign-out clearing) through `cookies().set`.

This makes sign-in, MFA, sign-out, password change, and trusted-device flows work as `<form action>` without client JavaScript. Rate limits, tenant authentication policies, session metadata (`clientInfo`), and audit events behave as they do for browser calls. Next server actions check the `Origin` of the incoming POST themselves, so the forwarded cookie cannot be replayed cross-site.

Next only allows cookie writes in server actions and route handlers. A server component can call read-only methods (`client().identities.list(...)`). A method that issues a cookie throws an error naming the cookie.

### Auth forms

`iamNext.authActions(options)` returns server actions for complete authentication flows, and `@better-iam/next/client` has forms for each. Export the actions from a `'use server'` module and pass them to the forms:

```ts
// app/auth-actions.ts
'use server';
import { iamNext } from '@/lib/iam-next';

const auth = iamNext.authActions({ afterSignIn: '/dashboard', discover: true });
export const signIn = auth.signIn;
export const reauthenticate = auth.reauthenticate;
export const requestPasswordReset = auth.requestPasswordReset;
export const resetPassword = auth.resetPassword;
export const signUp = auth.signUp;
export const verifyEmail = auth.verifyEmail;
export const acceptInvitation = auth.acceptInvitation;
export async function signOut() {
  await auth.signOut();
}
```

Export each action as its own `const`: Next registers every export of a `'use server'` module as an action. `signOut` is wrapped because it takes no state.

| Action                   | Steps and intents                                                                                                                                           | Finishes with                                                                                                |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `signIn`                 | `password` or `send-code` then `code` (emailed sign-in code); then `mfa`, `email-code`, `recovery`, or `enroll` for the second factor; `cancel` starts over | redirect to a safe `next` (or `afterSignIn`); after enrollment the `done` step shows the recovery codes once |
| `reauthenticate`         | `password`, then the same second-factor intents                                                                                                             | redirect to `next`; the replaced session is ended                                                            |
| `requestPasswordReset`   | email (and organization)                                                                                                                                    | the `sent` step with the same notice whether or not the account exists                                       |
| `resetPassword`          | `tenantId` and `token` from the email link, new password, optional confirmation                                                                             | redirect to `loginPath?reset=1`                                                                              |
| `signUp` / `verifyEmail` | self-registration (`authentication.signUpEnabled`) / the email link                                                                                         | `sent`, or redirect to `loginPath?registered=1` / `?verified=1`                                              |
| `acceptInvitation`       | `kind` `member` or `owner`, `tenantId`, `token`, name, password, then enrollment when the tenant requires MFA                                               | redirect to `next`                                                                                           |
| `signOut`                | none                                                                                                                                                        | clears the cookie, also when the server no longer knows the session, and redirects to the login path         |

Every action takes `(previousState, formData)` and returns an `AuthFormState`: the `step`, an `error` (`code`, `message`, the offending `field`, `retryAfterMs` for `RATE_LIMITED`), the pending `mfa` challenge, `recoveryCodes`, a `notice`, and the non-secret `values` to refill the form. Passwords, codes, session tokens, and session records never enter it. The challenge travels in hidden fields rather than server memory, which is what lets a form with JavaScript disabled post its second step. The server still validates every challenge, so a forged field only ever fails.

- **Organization.** The actions find it from a `tenantId` field, an `org` slug (`tenants.lookup`), your `resolveTenant(form)`, or, with `discover: true`, the verified domain of the email (`domains.discover`).
- **Keeping a session.** "Keep me signed in" (`keepSignedIn`) sends `X-Better-IAM-Persistent`, so the cookie lasts or ends with the browser. Step-up keeps a browser-session cookie as one unless the form opts in. "Remember this device" (`rememberDevice`) on the authenticator step returns a device cookie that later sign-ins present automatically.
- **Error text.** `messages` overrides the text for any error code or notice.

The forms render unstyled semantic HTML (`<form data-better-iam="sign-in" data-step="mfa">`, `<div data-field="code">`). Labels are bound, errors are tied to their field with `aria-invalid` and `aria-describedby` and announced with `role="alert"`, notices use `role="status"`, and the first field of each step takes focus. Alternative steps are named submit buttons (`name="intent"`), so a form works with JavaScript disabled, and `useActionState` keeps it in place when JavaScript is on. `labels` overrides any text, and each form has a `*View` twin that takes `{ state, formAction, pending }` for your own container.

Passkey sign-in and passkey MFA need the WebAuthn ceremony in the browser. Use `better-iam/client/passkeys` with the typed client for those.

### Guarded mutations with `useActionState`

```tsx
// actions.ts
'use server';
export const rename = iamNext.action(
  async (session, _previous: unknown, form: FormData) => {
    const id = String(form.get('id'));
    await db.projects.rename(id, String(form.get('name')));
    revalidatePath(`/projects/${id}`);
    return { id };
  },
  {
    authorize: {
      action: 'projects:write',
      resource: ({ args: [, form] }) => ({ type: 'project', id: String(form.get('id')) }),
    },
  },
);
```

```tsx
// form.tsx
'use client';
const [state, formAction] = useActionState(rename, null);
// state?.ok === false → state.error.code is 'ACCESS_DENIED', 'UNAUTHENTICATED', 'RATE_LIMITED', ...
```

Pass the handler first and the spec second, so TypeScript infers the arguments from the handler's annotations and checks the `resource` callback against them.

## Organizations in the URL

`requireTenantSession({ slug })` resolves an alias with `tenants.lookup` (active tenants with active ancestors only) and requires a session in that tenant. Unknown aliases call `notFound()`. A visitor signed in to a different organization is sent to `/login?org={slug}&next=...`, so the login page can pre-select the organization or offer the account switcher (`links.list`). Put it in `app/[org]/layout.tsx`, and every page below it gets `tenant.tenantId` for authorization calls.

## Middleware

The middleware runs on the edge and cannot open the database. It only checks that the session cookie is present: `__Host-better-iam.session` on HTTPS and `better-iam.session` on loopback HTTP. Pages must still authenticate. A stale cookie gets through the middleware, and the page's `requireSession` then redirects.

- `publicPaths` takes globs (`*` within a segment, `**` across segments) that are added to the defaults: the login path and `/api/iam`. `protect` replaces the whole rule.
- `signedInRedirect` sends visitors who carry a cookie away from a bare login page. A login URL with `?next=` always renders. Server guards attach `?next=` (at least `/`) whenever they reject a request that still has a session cookie, so a stale cookie ends on the login page instead of looping between the guard and the middleware.
- `next: (init) => NextResponse.next(init)` forwards `x-better-iam-pathname` on every request that continues. `requireSession`, `page`, and `requireTenantSession` use it as the default `?next=`, so a deep link survives sign-in without passing `returnTo` by hand.

`safeRedirectPath(value, fallback)` accepts only same-origin paths. It rejects absolute URLs, `//host`, backslashes, and control characters. Run every `next` parameter through it before redirecting.

## Downstream services and webhooks

`iamNext.assertion({ tenantId, audience })` mints a short-lived HS256 assertion about the current session (the caller needs `iam:assertions:create` on `iam/{audience}`). A service that has only the derived key (`iam.assertionKey()`, kept in its environment) verifies it with `withAssertion` or `verifyAssertionToken` from `@better-iam/next/edge`. The verification runs on Web Crypto, including in edge route handlers and middleware, and follows the same rules as the server's `verifyAssertion`. Use `authorize(claims)` for extra requirements such as `claims.mfa` or a role. It answers 403 when that returns false.

Services that should verify with public keys instead of a shared key use session JWTs: a caller obtains one with `format: 'jwt'` from `sts.getSessionToken` or `roles.assume` (the deployment configures `sts.jwt`), and the service verifies it offline with `createSessionTokenVerifier` from `better-iam/session-tokens`, which imports nothing from Node and runs in middleware and edge route handlers:

```ts
// middleware.ts of the downstream Next.js service
import { createSessionTokenVerifier } from 'better-iam/session-tokens';
import { NextResponse, type NextRequest } from 'next/server';

const verifier = createSessionTokenVerifier({
  issuer: 'https://iam.example.com/api/iam',
  audience: 'https://reports.example.com',
  jwks: 'https://iam.example.com/api/iam/.well-known/jwks.json',
});

export async function middleware(request: NextRequest) {
  try {
    await verifier.verifyRequest(request);
    return NextResponse.next();
  } catch {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }
}
```

Offline verification sees revocation only when the token expires, so keep `sts.jwt.maxLifetimeSeconds` short or check `sts/getCallerIdentity` for sensitive requests.

`createWebhookHandler({ secret, onEvent })` receives your deployment's webhooks:

- It verifies `X-Better-IAM-Signature` over `{timestamp}.{body}` against every configured secret, so you can rotate by listing the new and the previous secret.
- It rejects timestamps more than five minutes old (`toleranceSeconds`) and bodies over 1 MiB (`maxBodyBytes`) before parsing.
- It answers 500 when `onEvent` throws, and Better IAM retries with exponential backoff. Deliveries can repeat after a timeout, so make `onEvent` idempotent on `event.id`.
- Events carry `sequence` and `hash` from the audit chain, so a consumer can detect gaps.

## Keeping server components in sync with the browser

A sign-in or sign-out that happens in the browser (through the typed client, a passkey ceremony, or a session that expired while the tab was open) changes the cookie, but App Router server components that already rendered keep showing the old identity until the next navigation. `IamNextProvider` from `@better-iam/next/client` wraps `IamProvider` and calls `router.refresh()` whenever the signed-in identity changes, so layouts and pages re-render with the new cookie. Seed it with `initialSession={await iamNext.sessionForClient()}` from the root layout, so the first render needs no fetch and doesn't trigger a refresh. `useSignOut({ redirectTo })` signs out, navigates, and refreshes in one call.

Server actions need none of this. Next re-renders the page after an action, and `getSession()` reads the cookies the action set.

## Pages Router

The same guarantees are available to `pages/` applications:

| Helper                          | Use                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `pages.handler()`               | `pages/api/iam/[...path].ts`. It re-encodes bodies Next already parsed; turn `bodyParser` off only for byte-exact protocol callbacks. |
| `pages.withSession(gssp, spec)` | `getServerSideProps`: redirect to login with `?next=`, `notFound` (or `authorize.redirectTo`) on denial, and the session in props.    |
| `pages.api(handler, spec)`      | API routes: session cookie or bearer session token, `authorize`, the JSON error envelope, JSON results, and 204 for `undefined`.      |
| `pages.client(req, res)`        | The in-process typed client. Issued cookies are appended to `res`, so API routes can sign people in and out.                          |
| `pages.getSession(req)`         | The session for any Node request with `headers`, or `null`.                                                                           |

`withSession` serializes the session through JSON before returning it, because Next requires serializable props.

## Step-up

Sensitive pages and operations can demand more than a valid session: `stepUp: { mfa?: true | 'fresh', maxAgeMs?: number }` on `page`, `route`, `apiRoute`, `action`, `pages.withSession`, `pages.api`, and `requireSession`. Guards check it after authenticating and before authorizing, with `checkStepUp(session, requirement, now)`, which you can also call yourself.

| Requirement    | Satisfied by                                                                                                                                                                                             | Refused with                                                            |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `mfa: true`    | a session that completed MFA, including one a remembered device let through, and impersonated or assumed-role sessions derived from one                                                                  | `MFA_REQUIRED` (`reason=mfa`)                                           |
| `mfa: 'fresh'` | a user session that verified a factor itself                                                                                                                                                             | `MFA_REQUIRED`, or `IMPERSONATION_RESTRICTED` for impersonation         |
| `maxAgeMs`     | `authenticatedAt` within the window (and not in the future), for user sessions and API keys; temporary credentials (role sessions, session tokens, anything derived from a source session) never qualify | `RECENT_AUTH_REQUIRED` (`reason=recent`), or `IMPERSONATION_RESTRICTED` |

Pages redirect to `stepUpPath` (or `stepUp.redirectTo`) with `?next=` and `?reason=`. A `ReauthenticateForm` posting to `authActions().reauthenticate` there asks for the password and then the second factor when the account has one. That issues a new session with a fresh `authenticatedAt`, ends the session it replaced, and returns to `next`. The server has no in-place upgrade, so a new session is the only way to prove recency.

Without `stepUpPath`, page guards throw an `IamError` whose `digest` is `BETTER_IAM_STEP_UP:<code>:<reason>`. Production builds pass only the digest to `error.tsx`, so match on that prefix there. `maxAgeMs` is independent of the server's `authentication.recentAuthenticationMs` (five minutes by default), which guards the server's own sensitive operations. Keep the two aligned when a page leads to such an operation. The `now` option replaces the clock for tests.

## Service credentials

`apiRoute(handler, spec)` is `route()` for machine callers: it authenticates with `iam.authenticate`, so API keys and assumed-role sessions work as well as browser sessions. The handler receives `{ principal, params }`. `principal` is an `IamPrincipal` copied field by field from the stored records (identity: id, tenant, name, email, kind, status; session: id, tenant, kind, MFA, method, `authenticatedAt`, `expiresAt`, role, impersonator, remembered device), never the records themselves, so token hashes and policies cannot leak into a response. `authorize` defaults to the tenant the credential acts in (the role's tenant for an assumed role). API keys never have MFA, and their `authenticatedAt` is their creation time, so `stepUp` effectively refuses them for `mfa` and limits their age for `maxAgeMs`.

Session tokens (`sts.getSessionToken`) and session JWTs (`format: 'jwt'`) are accepted the same way, with any `Authorization` scheme casing (`bearer` works); no code change is needed. `principal.session.kind` is `'user' | 'role' | 'api-key' | 'session-token'`, and `principal.session.sessionName` and `sourceIdentity` are copied only when the stored session has them, so responses built from existing principals keep their exact keys. `stepUp: { mfa: 'fresh' }` refuses role sessions and session tokens (they are never `kind: 'user'`), even one minted with an MFA code; use `mfa: true` to accept a session token whose `mfa` is set. Temporary credentials also never pass the server's own recent-authentication checks, so operations that require them answer `RECENT_AUTH_REQUIRED` for such callers. See [temporary credentials](temporary-credentials.md).

## Background work

The outbox (email, SMS, webhooks) and the event dispatcher need something to run them. On a long-lived Node server the examples use a `setInterval`. On Vercel and other serverless hosts, `createIamNext(iam, { dispatchAfterResponse: true })` uses Next's `after()` instead: every in-process `client()` call and every POST to the `handlers()` mount schedules one dispatch that runs once the response has been sent. A sign-in code or reset email therefore leaves within the same invocation.

- **Concurrency.** Runs are single-flight per instance, with the outbox and events on separate lanes so a slow event handler cannot hold up email. A call made during a run waits for it and triggers exactly one more.
- **Fallback.** Where `after()` cannot run (the Pages Router, or outside a request scope), the run starts immediately without being awaited.
- **Re-entrancy.** Inside an event handler or delivery callback, call `background.schedule()` rather than awaiting `dispatch()`.

`background.cron(options)` covers everything interactive traffic does not trigger: retries with backoff, quiet periods, and the periodic jobs.

```ts
// app/api/cron/route.ts
export const runtime = 'nodejs';
export const GET = iamNext.background.cron({
  secret: process.env.CRON_SECRET,
  tasks: {
    purge: { retentionMs: 30 * 86_400_000 },
    auditRetention: { retentionMs: 365 * 86_400_000 },
    digest: true,
    reminders: true,
    outbox: true,
    events: true,
  },
});
```

On Vercel, schedule it in `vercel.json`:

```json
{ "crons": [{ "path": "/api/cron", "schedule": "*/10 * * * *" }] }
```

- **Authentication.** The route requires `Authorization: Bearer <secret>` (Vercel Cron sends `CRON_SECRET` this way), compares it in constant time, and refuses to run anything when no secret is configured (500 `CRON_NOT_CONFIGURED`).
- **Order.** Jobs run first, then the outbox drain (repeated while batches come back full) and events, so the email a job queues leaves in the same run.
- **Results.** Each task is isolated. The response lists per-task results and `errors`, and is 500 if any task failed; unexpected failures read `TASK_FAILED` without internal detail and go to `background.onError`.
- **Audit retention.** `auditRetention` prunes every active tenant, or the `tenants` you list.

## Runtime notes

- Route handlers that touch `iam` need `export const runtime = 'nodejs'`. The edge helpers run anywhere.
- `iam.endpoint` gives `client()` the origin and base path. A custom `IamLike` without it can pass `baseURL` / `basePath` options; otherwise the origin is derived from `x-forwarded-host` / `host`, and it must be one of the server's trusted origins.
- The helpers never cache across requests. Memoization is scoped to one render, and there is no module-level session state.
