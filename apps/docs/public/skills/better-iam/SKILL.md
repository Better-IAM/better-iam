---
name: better-iam
description: Write correct Better IAM code (embeddable TypeScript authentication, authorization, multi-tenant organizations, and identity governance). Use when a project imports better-iam or @better-iam/* packages, or when asked to add sign-in, sessions, roles, permission checks, policies, organizations, SSO, or SCIM with Better IAM.
---

# Better IAM

Better IAM is a library you embed in a TypeScript server. One `betterIam(options)` instance owns authentication,
authorization, tenants, and auditing; it stores everything in your database through a storage adapter and serves
an HTTP API (default base path `/api/iam`) that a typed browser client calls.

## Ground rules

- Do not guess an API. Every package name, import path, `iam.api.<group>.<method>` call, option, and error code
  must come from the docs or the installed types. When unsure, read the page's Markdown (every docs URL plus `.md`)
  or use the docs MCP server at `https://better-iam.com/api/mcp` (`lookup_api_method`, `lookup_export`,
  `lookup_error_code`, `search`, `get_page`).
- Index of every page: https://better-iam.com/llms.txt
- When the docs and the installed version disagree, the TypeScript types of the installed package win: every
  server method is typed end to end from the `betterIam()` instance.
- Requirements: Node.js 22.12 or newer, ESM only (`"type": "module"` or a bundler), and the native modules
  `argon2` (password hashing) and `better-sqlite3` (SQLite adapter) must be allowed to run install scripts.

## Setup, in order

1. Install the umbrella package. It re-exports every `@better-iam/*` package as a subpath (`better-iam/client`,
   `better-iam/next`, `better-iam/adapter-postgres`, ...) and installs the `better-iam` CLI. The Nuxt module is the
   exception: install `@better-iam/nuxt` separately.

   ```bash
   npm i better-iam
   ```

2. Environment. `BETTER_IAM_SECRET` (at least 32 characters; generate with `npx better-iam secret --env >> .env`)
   and `BETTER_IAM_BASE_URL` (the public origin). Better IAM does not load `.env` files itself.

3. Configuration module. The application and the CLI both load it.

   ```js
   // better-iam.config.mjs
   import { postgresAdapter } from 'better-iam/adapter-postgres';

   export default {
     database: postgresAdapter({ connectionString: process.env.DATABASE_URL }),
     secret: process.env.BETTER_IAM_SECRET,
     baseURL: process.env.BETTER_IAM_BASE_URL,
     authentication: {
       // Required for invitations, verification links, and codes (DELIVERY_REQUIRED without it).
       sendEmail: async (message) => {
         /* send message.template to message.to with your mail provider */
       },
     },
     permissions: {
       resourceTypes: {
         document: { actions: ['documents:read', 'documents:write'], attributes: { ownerId: 'string' } },
       },
     },
     // Required for application-owned resource types (RESOURCE_RESOLVER_REQUIRED without it).
     // Load the owner tenant from YOUR database; never from the request.
     resolveResource: async ({ type, id }) => {
       const document = await findDocument(id);
       return { type, id, tenantId: document.tenantId, attributes: { ownerId: document.ownerId } };
     },
   };
   ```

   Other adapters: `sqliteAdapter({ filename })` from `better-iam/adapter-sqlite`,
   `libsqlAdapter({ url, authToken })` from `better-iam/adapter-libsql`.

4. The instance, in a server-only module (`lib/iam.ts` in Next.js, `server/iam.ts` in Nuxt,
   `src/lib/server/iam.ts` in SvelteKit, `app/iam.server.ts` in React Router):

   ```ts
   // iam.ts
   import { betterIam } from 'better-iam';
   import config from './better-iam.config.mjs';

   export const iam = betterIam(config);
   ```

5. Schema: `npx better-iam migrate` (safe to rerun), or `await iam.initialize()` before the first request.

6. Mount the handler. `iam.handler` is Web-standard (`Request` to `Response`); `iam.nodeHandler` is for Node `http`.

   | Framework | Mount |
   | --- | --- |
   | Next.js | `createIamNext(iam, { loginPath })` from `better-iam/next`; `export const { GET, POST, OPTIONS } = iamNext.handlers()` in `app/api/iam/[...path]/route.ts` with `export const runtime = 'nodejs'` |
   | Nuxt | `modules: ['@better-iam/nuxt']` in `nuxt.config.ts` |
   | SvelteKit | `createIamKit(iam, { loginPath })` from `better-iam/svelte/kit`; `export const handle = iamKit.handle` |
   | React Router | `createIamRouter(iam, { loginPath })` from `better-iam/react-router`; `export const middleware = [iamRouter.middleware]` in `app/root.tsx`; `loader` and `action` = `iamRouter.api` on route `api/iam/*` |
   | Express | `createIamExpress(iam, { loginPath })` from `better-iam/express`; `app.use(iamExpress.middleware)` BEFORE `express.json()` |
   | Hono | `createIamHono(iam, { loginPath })` from `better-iam/hono`; `app.use(iamHono.middleware)` |
   | Fastify | `createIamFastify(iam, { loginPath })` from `better-iam/fastify`; `await app.register(iamFastify.plugin)` |
   | NestJS | `IamModule.forRoot({ iam, guard: true, mount: true })` from `better-iam/nestjs`; `NestFactory.create(AppModule, { rawBody: true })` |
   | Node | `createServer(iam.nodeHandler)` |

7. Browser client. Import the instance with `import type` so no server code reaches the bundle:

   ```ts
   import { createIamClient } from 'better-iam/client';
   import type { iam } from './iam';

   export const client = createIamClient<typeof iam>();
   ```

8. First administrator: set `BETTER_IAM_ROOT_EMAIL`, `BETTER_IAM_ROOT_NAME`, and `BETTER_IAM_ROOT_PASSWORD`
   (at least 12 characters), then `npx better-iam bootstrap`. Check the setup with `npx better-iam doctor`.

## Calling the server API

Every method under `iam.api.<group>.<method>` has one of three shapes:

| Shape | Example |
| --- | --- |
| `(credential, input)` | `iam.api.roles.create(credential, { tenantId, name, permissions })` |
| `(credential)` | `iam.api.auth.getSession(credential)` |
| `(input)`, public | `iam.api.auth.signIn({ tenantId, email, password })`, `iam.api.tenants.lookup({ slug })` |

- A credential is `{ headers }` (the incoming request's headers: session cookie or `Authorization: Bearer`) or
  `{ token }` (a session token or API key you hold). It never carries a user ID or tenant ID.
- Framework helpers give the credential: `await iamNext.credential()` (Next.js), `req.iam.credential()` (Express),
  `c.get('iam').credential()` (Hono), `request.iam.credential()` (Fastify), `event.locals.iam.credential()`
  (SvelteKit), `iamRouter.helpers(args).credential()` (React Router).
- Over HTTP every method is `POST {basePath}/{group}/{method}`, for example `POST /api/iam/roles/create`.
  The browser client mirrors the server API without the credential argument: `client.roles.create({ ... })`.
- Every sign-in names a tenant (`tenantId`), because one email can belong to different identities in different
  organizations. Resolve it with `tenants.lookup({ slug })`.
- `auth.signIn` returns either a session (`{ token, ... }`) or an MFA challenge (`'mfaRequired' in result`);
  handle both.

## Authorization

- Enforce on the server, immediately before the protected work:

  ```ts
  import { iam } from './iam';

  await iam.require({
    headers: request.headers,
    tenantId: document.tenantId,
    action: 'documents:write',
    resource: { type: 'document', id: document.id },
  }); // throws IamError ACCESS_DENIED (403) or UNAUTHENTICATED (401)
  ```

- `iam.authorize({ ...same input })` returns `{ allowed, reason, matched }` instead of throwing.
- `client.authorize`, `client.authorizeMany` (up to 50 checks), `useAuthorize` (`@better-iam/react`,
  `@better-iam/vue`), and `<Can>` (`@better-iam/react`) are advisory: they decide what UI to render, never what is allowed. Always repeat the check with `iam.require`.
- `iam.listAccessible({ ...credential, tenantId, action, type })` lists the registered resources of one type a
  caller may act on.
- Roles: `iam.api.roles.create(credential, { tenantId, name, permissions })` (or `document`, or `policyIds`;
  passing both `permissions` and `document` fails with `INVALID_INPUT`). Grant with
  `iam.api.bindings.create(credential, { tenantId, roleId, subjectType: 'identity' | 'group', subjectId })`.
- Declare every resource type and action in `permissions.resourceTypes`, so roles and policies are validated
  when saved.

## Errors

- Server failures throw `IamError` (import from `better-iam`) with a stable `code` and an HTTP `status`. Branch on
  `error instanceof IamError && error.code === 'ACCESS_DENIED'`, never on the message.
- The browser client throws `IamClientError` (from `better-iam/client`), which does not extend `IamError` but keeps
  the same `code`.
- Common codes: `UNAUTHENTICATED` (401), `ACCESS_DENIED` (403), `INVALID_INPUT`, `INVALID_CREDENTIALS`,
  `MFA_REQUIRED`, `RECENT_AUTH_REQUIRED` (sensitive operations such as `tenants.create` need a session
  authenticated in the last five minutes), `RATE_LIMITED` (read `retryAfterMs`), `FEATURE_DISABLED`,
  `DELIVERY_REQUIRED`, `RESOURCE_RESOLVER_REQUIRED`. Full list: https://better-iam.com/docs/reference/errors.md

## Pitfalls

- Emails, SMS, and webhooks are queued in the database and sent only when `iam.auth.dispatchOutbox()` (or
  `npx better-iam outbox`) runs. Schedule it every minute in production.
- Self sign-up is off by default: `authentication.signUpEnabled: true` turns it on (email verification is then
  required by default). Without it, `auth.signUp` fails with `FEATURE_DISABLED`.
- The root administrator always needs an MFA-verified session; its first sign-in returns a challenge with
  `enrollmentRequired: true` (enroll with `auth.beginMfa` and `auth.confirmMfa`).
- Never build a credential or choose a tenant for an authorization decision from request body, query, or custom
  header data. Pass the request headers and let `resolveResource` load the resource's tenant from your database.
- Next.js: keep the server packages and native modules in `serverExternalPackages`, and use the Node.js runtime
  for the IAM route.
- Hono runs on `iam.handler`, so Node-only protocol mounts (the OAuth provider) need a Node adapter.
- Do not invent provider-migration or password-import helpers; check the migration guides first.

## Docs to read (Markdown)

| Task | Page |
| --- | --- |
| Install and mount | https://better-iam.com/docs/installation.md |
| First working setup and basic calls | https://better-iam.com/docs/quickstart.md |
| Method shapes and credentials | https://better-iam.com/docs/concepts/api.md |
| Typed browser client | https://better-iam.com/docs/concepts/client.md |
| Errors | https://better-iam.com/docs/concepts/error-handling.md |
| Roles and bindings | https://better-iam.com/docs/authorization/roles.md |
| Policy documents | https://better-iam.com/docs/authorization/policies.md |
| Batches and listAccessible | https://better-iam.com/docs/authorization/queries.md |
| Next.js | https://better-iam.com/docs/integrations/nextjs.md |
| Express, Hono, Fastify | https://better-iam.com/docs/integrations/express.md, https://better-iam.com/docs/integrations/hono.md, https://better-iam.com/docs/integrations/fastify.md |
| Plain Node.js `http` | https://better-iam.com/docs/integrations/node.md |
| Scheduled jobs | https://better-iam.com/docs/operations/jobs.md |
| Every API method | https://better-iam.com/docs/reference/api.md |
| Every option | https://better-iam.com/docs/reference/options.md |
| Every CLI command | https://better-iam.com/docs/reference/cli.md |
| Every package export | https://better-iam.com/docs/reference/exports.md |
