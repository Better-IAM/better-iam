# Express, Hono, and Fastify

`@better-iam/middleware` connects a `betterIam()` instance to the common server frameworks. The umbrella package exposes it as `better-iam/express`, `better-iam/hono`, `better-iam/fastify`, and `better-iam/middleware`. Every adapter does the same four things:

1. **Serves the IAM HTTP API.** Requests under the instance's `basePath` (`/api/iam`), plus any prefixes you add with `serve`, go to the IAM server. Express and Fastify use `iam.nodeHandler`, so node-only protocol mounts such as the OAuth provider work too.
2. **Adds per-request helpers** as `req.iam` (Express), `c.get('iam')` (Hono), or `request.iam` (Fastify).
3. **Guards routes.** `requireSession({ stepUp? })` and `authorize(action, { resource?, tenantId?, stepUp? })` check the session, then step-up, then authorization.
4. **Maps refusals.** API calls get the IAM JSON error envelope `{ error: { code, message } }` with the IAM status (401 / 403 / 429) and `Cache-Control: no-store`. Page navigations (a `GET` with `Accept: text/html`) are redirected to `loginPath?next=…` when signed out, or to `stepUpPath?next=…&reason=mfa|recent|impersonation` when the session must step up, if those options are set.

Guards also run a **CSRF check**. A `POST`/`PUT`/`PATCH`/`DELETE` authenticated by the session cookie, with no `Authorization` header, must carry an `Origin` of the app itself, the IAM origin, or one of `trustedOrigins`; a `Sec-Fetch-Site: same-origin` request also passes. Otherwise it is refused with `UNTRUSTED_ORIGIN`, or `CSRF_REJECTED` when there is no `Origin`. Session cookies are `SameSite=Lax`, which still sends them from sibling subdomains, so the check matters. Bearer tokens skip it. Set `csrf: false` only when something else already checks origins. Routes without a guard that change state should call `checkRequestOrigin` themselves.

NestJS, Next.js, Nuxt, and SvelteKit have their own integrations ([NestJS](nestjs.md), [Next.js](nextjs.md), [Nuxt](nuxt.md), [SvelteKit](sveltekit.md)). SvelteKit's is built on the same core.

## Express

```ts
import express from 'express';
import { createIamExpress } from 'better-iam/express';
import type { IamRequest } from 'better-iam/middleware';
import { iam } from './iam.js';

declare global {
  namespace Express {
    interface Request {
      iam: IamRequest<typeof iam>;
    }
  }
}

const iamExpress = createIamExpress(iam, { loginPath: '/login', stepUpPath: '/verify' });
const app = express();
app.use(iamExpress.middleware); // before express.json(): the IAM server reads the raw body
app.use(express.json());

app.get('/me', iamExpress.requireSession(), async (req, res) => {
  const session = await req.iam.getSession();
  res.json({
    email: session!.identity.email,
    canInvite: await req.iam.can('iam:identities:create'),
  });
});
app.get(
  '/projects/:id',
  iamExpress.authorize('projects:read', {
    resource: (req) => ({ type: 'project', id: req.params.id }),
  }),
  (req, res) => res.json(loadProject(req.params.id)),
);
app.post('/login', async (req, res) => {
  // The in-process client sets the session cookie on this response.
  await req.iam.client.auth.signIn({
    tenantId,
    email: req.body.email,
    password: req.body.password,
  });
  res.redirect(303, '/');
});
app.use(iamExpress.errorHandler); // refusals thrown by routes (req.iam.require, iam.api.*) → JSON / redirect
```

Mount the middleware before body parsers. If a parser runs first, the adapter re-serialises the parsed body for the IAM API. That works for the JSON API, but node-only protocol mounts need the untouched stream. Mounting under a path (`app.use('/api/iam', iamExpress.middleware)`) works too, because the adapter restores the path Express strips. Express 4 and 5 are both supported.

## Hono

```ts
import { Hono } from 'hono';
import { createIamHono, type IamVariables } from 'better-iam/hono';

const iamHono = createIamHono(iam, { loginPath: '/login' });
const app = new Hono<{ Variables: IamVariables<typeof iam> }>();
app.use(iamHono.middleware);
app.get('/me', iamHono.requireSession(), async (c) =>
  c.json((await c.get('iam').getSession())!.identity),
);
app.get('/admin', iamHono.authorize('iam:identities:read'), (c) => c.text('admin'));
app.onError(iamHono.onError);
```

Hono calls the IAM server through its fetch handler (`iam.handler`), so it runs anywhere Hono does. Node-only protocol mounts (the OAuth provider) are not reachable through it, so serve those from a Node adapter. `onError` answers IAM refusals and `HTTPException`s. Any other error is logged and answered with a plain 500, as Hono's default handler does.

## Fastify

```ts
import Fastify from 'fastify';
import { createIamFastify } from 'better-iam/fastify';
import type { IamRequest } from 'better-iam/middleware';

declare module 'fastify' {
  interface FastifyRequest {
    iam: IamRequest<typeof iam>;
  }
}

const iamFastify = createIamFastify(iam, { loginPath: '/login' });
const app = Fastify();
await app.register(iamFastify.plugin); // not encapsulated, like fastify-plugin
app.get('/admin', { preHandler: iamFastify.authorize('iam:identities:read') }, handler);
app.setErrorHandler(iamFastify.errorHandler);
```

The plugin answers the IAM API in an `onRequest` hook, before Fastify parses the body, and hands the raw request to `iam.nodeHandler`.

## Per-request helpers

| Member                                      | Returns / does                                                                                  |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `getSession()`                              | The session, or `null` (memoized for the request)                                               |
| `requireSession({ stepUp? })`               | The session, or throws `IamRequestError` (401, or 403 with `reason`)                            |
| `require(action, resource?, { tenantId? })` | Throws the server's refusal when not allowed                                                    |
| `can(action, resource?, { tenantId? })`     | An advisory boolean; checks made in the same tick share one `authorizeMany` call                |
| `authorize(checks, { tenantId? })`          | `{ action, resource, allowed, reason }[]`                                                       |
| `listAccessible({ action, type, ... })`     | The managed resources the caller may act on                                                     |
| `assertion({ tenantId, audience, ... })`    | A signed assertion for a downstream service                                                     |
| `client`                                    | A typed client calling the IAM handler in process; its `Set-Cookie` answers go on this response |
| `credential()`                              | `{ headers }` for `iam.api.*` calls, including cookies set earlier in the request               |
| `signOut()`                                 | Ends the session and clears its cookie                                                          |

The resource defaults to the tenant (`iam/{tenantId}`), and the tenant to the session's. The package root exports the framework-neutral pieces for other frameworks: `createRequestHelpers(resolveIam, { url, headers, setCookie })`, `enforceGuard`, `refusalResponse`, `checkStepUp`, `safeRedirectPath`, `IamRequestError`, and `isIamRefusal`.

## Machine credentials and session JWTs

`requireSession` and the `authorize` guards build on `auth.getSession`, which serves signed-in people only, so API keys and [temporary credentials](temporary-credentials.md) (role sessions, session tokens from `sts.getSessionToken`, and session JWTs) are refused there with 401. Machine routes check them through the helpers instead, which pass the request's `Authorization` header (any scheme casing) to the server: `req.iam.require(action, resource, { tenantId })` and `req.iam.can(…)` with an explicit `tenantId`, or `iam.api.*` calls with `req.iam.credential()`. `iam.api.sts.getCallerIdentity(req.iam.credential())` tells such a route who is calling (identity, tenant, session kind, role, session name). Bearer requests skip the CSRF check, and temporary credentials never pass the server's recent-authentication checks.

Services that are not the IAM application verify session JWTs offline with `createSessionTokenVerifier` from `better-iam/session-tokens` (runtime-neutral, so it also runs under Hono on workers):

```ts
import { createSessionTokenVerifier } from 'better-iam/session-tokens';

const verifier = createSessionTokenVerifier({
  issuer: 'https://iam.example.com/api/iam',
  audience: 'https://reports.example.com',
  jwks: 'https://iam.example.com/api/iam/.well-known/jwks.json',
});

// Express
app.use('/reports', async (req, res, next) => {
  try {
    res.locals.claims = await verifier.verifyRequest({
      headers: { authorization: req.get('authorization') ?? '' },
    });
    next();
  } catch {
    res
      .status(401)
      .json({ error: { code: 'UNAUTHENTICATED', message: 'A valid session token is required' } });
  }
});

// Hono
app.use('/reports/*', async (c, next) => {
  try {
    await verifier.verifyRequest(c.req.raw);
  } catch {
    return c.json(
      { error: { code: 'UNAUTHENTICATED', message: 'A valid session token is required' } },
      401,
    );
  }
  await next();
});

// Fastify
app.addHook('onRequest', async (request, reply) => {
  try {
    await verifier.verifyRequest({
      headers: { authorization: request.headers.authorization ?? '' },
    });
  } catch {
    return reply
      .code(401)
      .send({ error: { code: 'UNAUTHENTICATED', message: 'A valid session token is required' } });
  }
});
```

The verifier throws `SessionTokenError` (`reason` is for logs only). It learns of revocation only when a token expires, so keep `sts.jwt.maxLifetimeSeconds` short or call `sts/getCallerIdentity` for sensitive requests.
