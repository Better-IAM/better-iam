# @better-iam/next

Next.js App Router integration for Better IAM. Requires Next.js 15 and React 19.

- **Sessions in server components**: `getSession` / `requireSession`, memoized per request with React `cache`.
- **Guards**: `page()` for pages and layouts, `route()` for route handlers, `action()` for server actions, `require()` and `can()` for one-off checks.
- **Rendering by permission**: `<iamNext.Can>` server component and `allowed()`, batched per request into one `authorizeMany`.
- **Server-side typed client**: `client()` calls the IAM handler in process and writes the cookies it issues through `cookies()`, so server actions can sign people in and out without client JavaScript.
- **Organizations**: `requireTenantSession({ slug })` for `/[org]/...` routes.
- **Middleware**: redirect signed-out visitors, public path globs, signed-in redirects away from the login page, and path forwarding so `?next=` fills itself.
- **Pages Router**: `pages.withSession` for `getServerSideProps`, `pages.api` for API routes, `pages.client`, and `pages.handler()`.
- **Auth forms**: `authActions()` returns drop-in server actions (sign-in with MFA, enrollment, recovery and emailed codes, emailed sign-in codes, step-up, sign-out, password reset, sign-up, email verification, invitations), and `@better-iam/next/client` has matching unstyled, accessible forms that work without client JavaScript.
- **Step-up**: `stepUp: { mfa, maxAgeMs }` on pages, routes, actions, and Pages Router guards sends people to a re-authentication page, or answers 403.
- **Service credentials**: `apiRoute()` accepts API keys and assumed roles as well as sessions, and hands the handler a sanitized principal.
- **Background work**: `dispatchAfterResponse` delivers email and webhooks after responses with `after()`, and `background.cron()` is a bearer-protected route for schedulers.
- **Client components** (`@better-iam/next/client`): `IamNextProvider` refreshes server components when the session changes in the browser, plus `useSignOut`.
- **Edge helpers** (`@better-iam/next/edge`, no Node or React imports): offline assertion verification (`verifyAssertionToken`, `withAssertion`), a webhook receiver (`createWebhookHandler`), and `safeRedirectPath` against open redirects.

```ts
// lib/iam-next.ts
import { createIamNext } from '@better-iam/next';
import { iam } from './iam';

export const iamNext = createIamNext(iam, { loginPath: '/login' });
```

```ts
// app/api/iam/[...path]/route.ts
import { iamNext } from '@/lib/iam-next';
export const runtime = 'nodejs';
export const { GET, POST, OPTIONS } = iamNext.handlers();
```

## Pages and layouts

```tsx
// app/projects/[id]/page.tsx
import { iamNext } from '@/lib/iam-next';

export default iamNext.page(
  async (props: { params: Promise<{ id: string }> }, { session, params }) => {
    const access = await iamNext.can({
      tenantId: session.session.tenantId,
      checks: [{ action: 'projects:manage', resource: { type: 'project', id: params.id } }],
    });
    return <main>{access[`projects:manage@project/${params.id}`] && <button>Manage</button>}</main>;
  },
  {
    authorize: {
      action: 'projects:read',
      resource: ({ params }) => ({ type: 'project', id: params.id }),
      redirectTo: '/forbidden',
    },
  },
);
```

Signed-out visitors go to the login path with `?next=`; denied visitors go to `authorize.redirectTo`. Without `redirectTo`, the denial throws the server's `IamError`, or calls `forbidden()` when `interrupts: true` is set (Next's `experimental.authInterrupts`, rendering `forbidden.tsx` / `unauthorized.tsx`). The lower-level `requireSession({ returnTo })` and `require({ tenantId, action, resource, redirectTo })` remain available.

`getSession()` with no argument is memoized for the request, so a layout and its page share one database round trip. Pass `headers` to read another request.

## Rendering by permission

```tsx
// Any server component: sibling checks share one authorizeMany round trip per request.
<iamNext.Can
  action="projects:manage"
  resource={{ type: 'project', id }}
  fallback={<ReadOnlyBadge />}
>
  <ManageButton />
</iamNext.Can>;

const canInvite = await iamNext.allowed('iam:identities:create'); // tenant defaults to the session's
```

`allowed()` queues each check until the current render yields, then answers the whole queue with `authorizeMany`: deduplicated, 50 checks per call, one queue per tenant. Answers are reused for the rest of the request (React `cache` scope), and signed-out requests get `false` without a call. Like `can()`, these are advisory; enforce the operation itself.

## Server actions

```ts
'use server';
import { iamNext } from '@/lib/iam-next';

// Any IAM call from an action: cookies the server issues are written with cookies().set.
export async function revokeOtherDevices() {
  await iamNext.client().auth.revokeOtherSessions();
}

// Guarded mutation: failures come back as { ok: false, error: { code, message } } for useActionState.
export const renameProject = iamNext.action(
  async (session, id: string, name: string) => {
    /* ... */
    return { id, name };
  },
  {
    authorize: {
      action: 'projects:write',
      resource: ({ args: [id] }) => ({ type: 'project', id }),
    },
  },
);
```

`client()` is the full typed API (`createIamClient<typeof iam>`) bound to the current request. It calls `iam.handler` in process with the caller's cookies, user agent, and forwarding headers, so the server's CSRF boundary, trusted-device cookie, session metadata, rate limits, and audit trail all apply. Cookies it issues are written with `cookies().set`, which Next allows only in server actions and route handlers; calling a cookie-changing method from a server component throws. Sign-in failures reject with an `IamClientError` carrying the server's `code`.

## Route handlers

```ts
// app/api/projects/[id]/route.ts
export const GET = iamNext.route<{ id: string }>(
  async (request, { session, params }) => ({ id: params.id, viewer: session.identity.id }),
  {
    authorize: {
      action: 'projects:read',
      resource: ({ params }) => ({ type: 'project', id: params.id }),
    },
  },
);
```

The session comes from the request's session cookie or a bearer session token; use `apiRoute()` for API keys and assumed roles. IAM failures (`IamError` and `IamClientError`) answer the JSON error envelope with the server's status (401, 403, 429, ...); other errors propagate unchanged, so internal messages never reach the response. Other results are sent as JSON, `undefined` answers 204, and a `Response` passes through.

Cookie-authenticated mutations (any method but GET, HEAD, and OPTIONS, carrying the session cookie and no `Authorization` header) must come from this application's origin, the IAM origin, or an entry in the `trustedOrigins` option. Otherwise the wrapper answers 403 with `CSRF_REJECTED` or `UNTRUSTED_ORIGIN`, the same rule the IAM handler applies. `route()`, `apiRoute()`, and `pages.api()` all enforce it.

## API keys and service credentials

````ts
// app/api/reports/route.ts: callable by browsers, API keys, and assumed roles
export const GET = iamNext.apiRoute(
  async (request, { principal }) => ({ caller: principal.identity.id, kind: principal.session.kind }),
  { authorize: { action: 'reports:read' } },
);
```n
`apiRoute()` authenticates any credential the server accepts through `iam.authenticate` and passes a whitelisted `IamPrincipal` (identity id, tenant, name, email, kind, and status; session id, tenant, kind, MFA, method, times, role, and impersonator), never the stored records. `authorize` defaults to the tenant the credential acts in. API keys never have MFA, so `stepUp.mfa` refuses them.

## Step-up

```tsx
// app/settings/security/page.tsx: needs a sign-in within the last five minutes, verified with a second factor
export default iamNext.page(async (props, { session }) => <SecuritySettings session={session} />, {
  stepUp: { maxAgeMs: 5 * 60_000, mfa: true },
});

// lib/iam-next.ts
export const iamNext = createIamNext(iam, { loginPath: '/login', stepUpPath: '/reauth' });
```n
```tsx
// app/reauth/page.tsx
import { ReauthenticateForm } from '@better-iam/next/client';
import { reauthenticate } from '../auth-actions';
export default async function Reauth(props: { searchParams: Promise<{ next?: string }> }) {
  const { next } = await props.searchParams;
  await iamNext.requireSession();
  return <ReauthenticateForm action={reauthenticate} next={next} />;
}
```n
The order is authenticate, then step-up, then authorize. A session that falls short (`checkStepUp` explains why: `MFA_REQUIRED`, `RECENT_AUTH_REQUIRED`, or `IMPERSONATION_RESTRICTED`) sends pages and `pages.withSession` to `stepUpPath?next=...&reason=mfa|recent|impersonation`. Route handlers, `apiRoute()`, and `pages.api()` answer 403 with the code, and `action()` returns it as an `ActionResult`.

- `mfa: true` accepts any session that completed MFA, including one a remembered device let through.
- `mfa: 'fresh'` requires a user session that verified a factor itself. It refuses remembered devices, impersonation, assumed roles, and API keys.
- `maxAgeMs` compares `session.authenticatedAt` with `now`. Impersonated sessions never qualify, as on the server.

Without a `stepUpPath`, page guards throw an `IamError` whose `digest` is `BETTER_IAM_STEP_UP:<code>:<reason>`, which survives into `error.tsx` in production builds. Re-authentication issues a new session: the `reauthenticate` action ends the one it replaced and keeps a browser-session cookie a browser-session cookie.

## Organizations

```tsx
// app/[org]/layout.tsx
export default async function OrgLayout(props: {
  params: Promise<{ org: string }>;
  children: React.ReactNode;
}) {
  const { org } = await props.params;
  const { tenant, session } = await iamNext.requireTenantSession({ slug: org });
  return (
    <Shell tenant={tenant} session={session}>
      {props.children}
    </Shell>
  );
}
````

Unknown aliases call `notFound()`. Visitors who are signed out, or signed in to another organization, go to `/login?org={slug}&next=...`. `iamNext.tenant(slug)` resolves an alias without requiring a session.

## Middleware

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { createIamMiddleware } from '@better-iam/next/edge';

export const middleware = createIamMiddleware({
  loginPath: '/login',
  publicPaths: ['/', '/pricing', '/docs/**', '/invite/*'],
  signedInRedirect: '/dashboard',
  next: (init) => NextResponse.next(init),
});
export const config = { matcher: ['/((?!_next|favicon.ico).*)'] };
```

The middleware checks only that the session cookie is present, because the edge runtime cannot open the database; pages still enforce. With `next`, continuing requests carry `x-better-iam-pathname`, which `requireSession`, `page`, and `requireTenantSession` use as the default `?next=`. Visitors who carry a cookie and open the login page without `?next=` go to `signedInRedirect`. With `?next=` the page renders, because server guards add it when they find the cookie stale (revoked, expired, or from a reset database), and bouncing such visitors back would loop.

## Background work

````ts
// lib/iam-next.ts: email, SMS, webhooks, and events go out after each response (Next's after())
export const iamNext = createIamNext(iam, { dispatchAfterResponse: true });

// app/api/cron/route.ts: point Vercel Cron, GitHub Actions, or any scheduler here
export const GET = iamNext.background.cron({
  secret: process.env.CRON_SECRET,
  tasks: { outbox: true, events: true, purge: true, reminders: true, digest: true },
});
```n
With `dispatchAfterResponse`, every call through `client()` and `pages.client()`, and every POST to `handlers()` or `pages.handler()`, schedules `background.schedule()`: `after()` runs the outbox and event dispatch once the response has been sent, so a sign-in code or reset email needs no separate worker. Runs are single-flight per instance (outbox and events on separate lanes, so a slow event handler never holds back email), and where `after()` is unavailable (the Pages Router, outside a request) the run starts at once without being awaited.

`background.cron(options)` is a GET/POST route handler that requires `Authorization: Bearer <secret>` (`CRON_SECRET` by default) and fails closed when no secret is configured. It runs the enabled jobs (`purge`, `auditRetention`, `digest`, `reminders`) and then the `outbox` drain and `events`, each isolated. It answers 200 with per-task results when all succeed, and 500 with `errors` otherwise; unexpected failures appear as `TASK_FAILED` without internal detail. `background.dispatch()` runs a pass immediately.

## Pages Router

```ts
// pages/api/iam/[...path].ts
import { iamNext } from '@/lib/iam-next';
export default iamNext.pages.handler();
````

```tsx
// pages/projects/[id].tsx
export const getServerSideProps = iamNext.pages.withSession(
  async (context, { session }) => ({ props: { id: String(context.params?.id) } }),
  {
    authorize: {
      action: 'projects:read',
      resource: ({ params }) => ({ type: 'project', id: String(params.id) }),
    },
  },
);
export default function Project({
  id,
  session,
}: {
  id: string;
  session: { identity: { name: string } };
}) {
  return (
    <h1>
      {id} for {session.identity.name}
    </h1>
  );
}
```

```ts
// pages/api/projects/[id].ts
export default iamNext.pages.api(async (req, res, { session }) => ({ id: req.query.id }), {
  authorize: {
    action: 'projects:read',
    resource: ({ req }) => ({ type: 'project', id: String(req.query.id) }),
  },
});
```

`withSession` redirects signed-out visitors to the login path with `?next=` (the resolved URL), answers `notFound` on denial (or redirects to `authorize.redirectTo`), and adds the session to the props as JSON. `pages.api` answers IAM failures with the JSON error envelope and status. `pages.client(req, res)` is the in-process typed client for API routes, and it appends issued cookies to `res`. `pages.handler()` accepts bodies Next has already parsed, so `bodyParser` can stay on.

## Client components

```tsx
// app/providers.tsx
'use client';
import { createIamClient } from 'better-iam/client';
import { IamNextProvider } from '@better-iam/next/client';
import type { iam } from '@/lib/iam';

const client = createIamClient<typeof iam>();
export function Providers({
  initialSession,
  children,
}: {
  initialSession: unknown;
  children: React.ReactNode;
}) {
  return (
    <IamNextProvider client={client} initialSession={initialSession as never}>
      {children}
    </IamNextProvider>
  );
}
```

`IamNextProvider` is `IamProvider` plus `useRouterSync()`: when the signed-in identity changes in the browser (sign-in, sign-out, account switch, or an expired session noticed on focus), it calls `router.refresh()`, so server components re-render with the new cookies. `useSignOut({ redirectTo })` signs out, navigates, and refreshes. The entry re-exports `useSession`, `useAuthorize`, `useAccessible`, `useIamClient`, and `Can`.

## Auth forms

````ts
// app/auth-actions.ts
'use server';
import { iamNext } from '@/lib/iam-next';

const auth = iamNext.authActions({ afterSignIn: '/dashboard' });
export const signIn = auth.signIn;
export const reauthenticate = auth.reauthenticate;
export const requestPasswordReset = auth.requestPasswordReset;
export const resetPassword = auth.resetPassword;
export const acceptInvitation = auth.acceptInvitation;
export async function signOut() {
  await auth.signOut();
}
```n
```tsx
// app/login/page.tsx
import { SignInForm } from '@better-iam/next/client';
import { signIn } from '../auth-actions';

export default async function Login(props: { searchParams: Promise<{ next?: string; org?: string }> }) {
  const { next, org } = await props.searchParams;
  return <SignInForm action={signIn} next={next} org={org} keepSignedIn passwordless />;
}
```n
The actions take `(previousState, formData)` for `useActionState` and return an `AuthFormState` (`step`, `error`, `mfa`, `recoveryCodes`, `notice`, echoed non-secret `values`). `signIn` walks the whole flow from one form: password or an emailed sign-in code, then an authenticator code, an emailed code, a recovery code, or first-time enrollment (it shows the secret, then the recovery codes once), with 'keep me signed in' and 'remember this device' carried through. The organization comes from a `tenantId` field, an `org` slug, `resolveTenant`, or, with `discover`, the email's verified domain. Every redirect goes through `safeRedirectPath`, and neither passwords, codes, nor tokens ever appear in the state.

The forms (`SignInForm`, `ReauthenticateForm`, `PasswordResetRequestForm`, `PasswordResetForm`, `SignUpForm`, `InvitationForm`) render plain semantic HTML with `data-better-iam`, `data-step`, and `data-field` hooks for styling, labels you can override, `role="alert"` errors tied to their field, and focus on the first field of each step. Everything a step needs travels in hidden fields and named submit buttons, so they keep working with JavaScript disabled. Each has a pure `*View` twin for custom containers and tests.

## Hydrating client components

```tsx
// app/layout.tsx (server component)
const initialSession = await iamNext.sessionForClient();
return <Providers initialSession={initialSession}>{children}</Providers>; // <IamProvider initialSession=...>
````

## Edge helpers

```ts
// A downstream service verifying assertions minted with iamNext.assertion(), without a database.
import { withAssertion } from '@better-iam/next/edge';
export const runtime = 'edge';
export const GET = withAssertion(
  { key: process.env.IAM_ASSERTION_KEY!, audience: 'reports', authorize: (claims) => claims.mfa },
  async (request, { claims }) => Response.json({ tenant: claims.tid, user: claims.sub }),
);
```

```ts
// app/api/webhooks/iam/route.ts: receive Better IAM webhooks.
import { createWebhookHandler } from '@better-iam/next/edge';
export const POST = createWebhookHandler({
  secret: [process.env.IAM_WEBHOOK_SECRET!, process.env.IAM_WEBHOOK_SECRET_PREVIOUS!].filter(
    Boolean,
  ),
  onEvent: async (event, delivery) => {
    if (event.type === 'identity:delete') await removeProfile(event.resourceId);
  },
});
```

`verifyAssertionToken` follows the server's `verifyAssertion` rules (HS256, audience, optional issuer, 30 seconds of clock tolerance) and `verifyWebhook` matches `verifyWebhookSignature`, both with Web Crypto. The webhook handler rejects unsigned, stale (over five minutes), and oversized bodies before calling `onEvent`, and answers 500 when `onEvent` throws so the sender retries; deliveries may repeat, so deduplicate on `event.id`.

`iamNext.assertion({ tenantId, audience })` issues the token for the current session (the caller needs `iam:assertions:create` on `iam/{audience}`); the receiving service gets the key from `iam.assertionKey()`.

License: Apache-2.0.
