# @better-iam/middleware

Express, Hono, and Fastify integrations for Better IAM. Each one serves the IAM HTTP API (including node-only protocol mounts on Express and Fastify), adds per-request helpers (`req.iam`, `c.get('iam')`, `request.iam`), and provides `requireSession` / `authorize` route guards. Refusals become the IAM JSON error envelope, or a login / step-up redirect for page navigations.

```ts
import { createIamExpress } from '@better-iam/middleware/express';

const iamExpress = createIamExpress(iam, { loginPath: '/login' });
app.use(iamExpress.middleware); // before body parsers
app.get('/admin', iamExpress.authorize('iam:identities:read'), handler);
app.use(iamExpress.errorHandler);
```

Entry points:

- `@better-iam/middleware/express`: `createIamExpress`
- `@better-iam/middleware/hono`: `createIamHono`, `IamVariables`
- `@better-iam/middleware/fastify`: `createIamFastify`
- `@better-iam/middleware`: the framework-neutral core (`createRequestHelpers`, `enforceGuard`, `refusalResponse`, `checkStepUp`, `safeRedirectPath`, `IamRequestError`)

Guide: [docs/node-frameworks.md](../../docs/node-frameworks.md).
