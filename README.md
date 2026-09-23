# Better IAM

An embeddable TypeScript authentication, identity provisioning, and access-management platform. Better IAM runs in your application with your database. It is independent of Better Auth and uses maintained protocol and cryptographic libraries.

**Version 0.1.0 · Node.js 22.12+ · PostgreSQL, SQLite, and libSQL/Turso · MIT**

```sh
npm install better-iam
```

## What it includes

- Tenant trees with configurable types, isolated identity directories, root administration, owner and member invitations, sign-in aliases, explicit account linking, tenant move/rename administration, data-subject exports, tenant-wide session revocation, and retention purging. Each tenant is an account that many people sign in to with their own identities and roles.
- A configurable resource catalog: declared resource types with actions, typed attributes, and relations, IAM-managed resources with owners and parents, relationship tuples for sharing (`resource.relations`), typed identity attributes (`principal.{name}`), tenant-defined resource types and actions, custom roles built from permissions or conditional policies with twenty-one operators, groups, versioned JSON policies with `${principal.id}` variables, inherited boundaries, delegated grant authorities, batch authorization for UIs, and reverse queries that list the resources a person may act on.
- Temporary bindings with expiry, eligible bindings activated just in time (bounded, justified, MFA-gated, audited), access requests with reviewer approval under the reviewer's own authority, access reviews (who can do what, and what an identity can do), scheduled deactivation of contractors and temporary service accounts, labeled API keys with last-use tracking and unused-key reports, configuration as code (export, plan, and apply a tenant's access model by name), and platform-controlled cross-tenant role assumption.
- Passwords, verification and recovery, database sessions with device metadata and sign-out-everywhere, magic links, email/SMS codes, TOTP/recovery codes with "remember this device", passkeys, configurable rate limits, per-tenant authentication policies (required MFA, allowed methods, session lifetimes and caps, remembered-device windows), and audited administrator impersonation ("view as") that policies, sessions, and audit records can all see.
- STS-style temporary credentials: AssumeRole parity (session names, source identities, session tags, per-trust duration caps, scope-down policies, and revoke-older-sessions watermarks), `sts.getSessionToken` for short-lived, optionally MFA-attested tokens from a session or API key, `sts.getCallerIdentity` (CLI `whoami`), typed and checksummed `biam_…` tokens that secret scanners recognize, and session-aware policy keys (`principal.tokenIssueTime`, `principal.mfaTime`, `principal.sessionTags.<key>`, `request.sourceIp`, …). See [temporary credentials](docs/temporary-credentials.md).
- Signed session JWTs (EdDSA/ES256) with a JWKS route and key rotation, verified offline by other services with the runtime-neutral `createSessionTokenVerifier` (`better-iam/session-tokens`), while IAM itself still checks every token against its stored session.
- OIDC web-identity federation (AssumeRoleWithWebIdentity): GitHub Actions, GitLab, Kubernetes, and cloud workloads exchange their platform token for a role session under tenant-managed OIDC providers and claim-conditioned trusts, with no stored secret, single-use replay protection, and an SSRF-guarded key fetch.
- OAuth/OIDC sign-in, Google/GitHub, a persistent OAuth/OIDC provider with device authorization, SAML SSO, and SCIM Users/Groups.
- A tamper-evident audit log (per-tenant hash chain with verification and export), events on every audit record, signed webhooks per tenant, in-process subscribers, observability spans with built-in Prometheus metrics and health endpoints, stateless service assertions, a typed browser client with React hooks, Next.js helpers, Vue composables, and a Nuxt module, SQL adapters, CLI, plugins, a reference tenant-scoped Projects plugin, filterable audit records, and an encrypted transactional delivery outbox.

The workspace contains separately publishable `@better-iam/*` packages. The umbrella `better-iam` package installs them together and exposes subpath imports. Protocol packages are loaded only when their subpaths are imported. CI (`.github/workflows/ci.yml`) publishes to npm when a new version lands on `main` and every check passes.

## Develop locally

```sh
pnpm install
pnpm build
pnpm test
pnpm check
pnpm pack:all
node scripts/packed-smoke.mjs
```

The package names are publication targets; install from this workspace or its packed artifacts until a release has actually been published.

```ts
import { betterIam } from 'better-iam';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';

export const iam = betterIam({
  database: sqliteAdapter({ filename: './iam.db' }),
  secret: process.env.BETTER_IAM_SECRET!,
  baseURL: 'https://identity.example.com',
  authentication: {
    sendEmail: async (message) => {
      // Deliver with your transport. Deduplicate retries using message.id.
      await delivery.send(message);
    },
  },
  permissions: {
    mode: 'tenant-defined', // organizations may also define their own resource types and actions
    resourceTypes: {
      document: {
        actions: ['documents:read', 'documents:write'],
        attributes: { ownerId: 'string' },
      },
      project: {
        managed: true,
        actions: ['projects:read', 'projects:manage'],
        attributes: { archived: 'boolean' },
      },
    },
  },
  resolveResource: async ({ tenantId, type, id }) => {
    const document = await documents.find(id);
    return { tenantId: document.tenantId, type, id, attributes: { ownerId: document.ownerId } };
  },
});

await iam.initialize(); // Explicit migration step; normally run using the CLI.
```

`delivery` and `documents` above are application-owned integrations; `project` resources are registered with IAM (`iam.api.resources.register`) and need no resolver. The [SQLite example](examples/sqlite/README.md) and [PostgreSQL example](examples/postgres/README.md) contain runnable applications; the [Next.js example](examples/nextjs/README.md) shows the App Router integration ([guide](docs/nextjs.md)); the [NestJS example](examples/nestjs/README.md) shows the module, guard, and decorators ([guide](docs/nestjs.md)); the [Nuxt example](examples/nuxt/README.md) shows the Nuxt module ([guide](docs/nuxt.md)); the [SvelteKit example](examples/sveltekit/README.md) shows the hooks, guards, and stores ([guide](docs/sveltekit.md)); the [React Router example](examples/react-router/README.md) shows middleware, guarded loaders, and actions ([guide](docs/react-router.md)); Express, Hono, and Fastify apps use `better-iam/express`, `better-iam/hono`, and `better-iam/fastify` ([guide](docs/node-frameworks.md)).

```ts
// An organization owner shapes their account: a custom role, an invited member, and a tenant-defined resource type.
const editor = await iam.api.roles.create(ownerCredential, {
  tenantId,
  name: 'Editor',
  permissions: ['documents:read', 'documents:write', 'projects:read'],
});
await iam.api.identities.invite(ownerCredential, {
  tenantId,
  email: 'alice@example.com',
  roleIds: [editor.id],
});
await iam.api.resourceTypes.register(ownerCredential, {
  tenantId,
  name: 'invoice',
  actions: ['read', 'approve'],
  attributes: { amount: 'number' },
});
// Alice accepts from the delivered link, then signs in to the organization by alias.
const { tenantId: found } = await iam.api.tenants.lookup({ slug: 'acme' });
await iam.api.auth.signIn({ tenantId: found, email: 'alice@example.com', password });
```

## Use the server and client

```ts
import { createServer } from 'node:http';
createServer(iam.nodeHandler).listen(3000);

// A server call still supplies an actual credential.
await iam.require({
  headers: request.headers,
  tenantId: document.tenantId,
  action: 'documents:read',
  resource: { type: 'document', id: document.id },
});
```

```ts
import { createIamClient } from 'better-iam/client';
import type { iam } from './iam.js';

const client = createIamClient<typeof iam>({
  baseURL: 'https://identity.example.com',
  onUnauthenticated: () => router.push('/login'), // lapsed or revoked session, never a wrong password
  retryRateLimited: true, // retry once after the server's Retry-After when it is short
  requestId: true, // X-Request-Id on every call; IamClientError.requestId for support tickets
});
const { tenantId } = await client.tenants.lookup({ slug: 'acme' });
await client.auth.signIn({ tenantId, email, password });
const { results } = await client.authorizeMany({
  tenantId,
  checks: [{ action: 'projects:manage', resource: { type: 'project', id } }],
});
const { resources } = await client.listAccessible({
  tenantId,
  action: 'projects:read',
  type: 'project',
});
```

```tsx
// React: session state, batched advisory decisions, and permission-gated rendering.
import { IamProvider, useSession, Can } from 'better-iam/react';
<IamProvider client={client}>
  <Can tenantId={tenantId} action="iam:identities:create">
    <InviteButton />
  </Can>
</IamProvider>;

// Next.js App Router: guarded pages, route handlers, and server actions, plus a typed server-side client.
import { createIamNext } from 'better-iam/next';
export const iamNext = createIamNext(iam, { loginPath: '/login' });
export default iamNext.page(async (props, { session }) => <Dashboard session={session} />, {
  authorize: { action: 'projects:read' },
});
```

```ts
// NestJS: a global guard, declarative authorization, and the IAM API served by the Nest app.
import { IamModule, Authorize, CurrentIdentity } from 'better-iam/nestjs';
@Module({ imports: [IamModule.forRoot({ iam, guard: true, mount: true })] })
export class AppModule {}
```

```ts
// Nuxt: the module mounts the API in Nitro, renders sessions on the server, and guards pages from page meta.
export default defineNuxtConfig({
  modules: ['@better-iam/nuxt'],
  betterIam: { loginPath: '/login' },
});
definePageMeta({ iam: { action: 'projects:manage' } }); // in a page
const { session } = useIamSession(); // auto-imported; <IamCan> too
const { identity } = await requireIamSession(event); // in server routes
```

```ts
// SvelteKit: handle serves the API and guards sections; loads and form actions get typed helpers.
export const iamKit = createIamKit(iam, { protect: [{ path: '/app' }] }); // better-iam/svelte/kit
export const handle = iamKit.handle; // src/hooks.server.ts
export const load = iamKit.guard(async (event, session) => ({
  canManage: await event.locals.iam.can('projects:manage'),
}));
```

HTTP uses explicit `POST /api/iam/{group}/{method}` endpoints with JSON, the `X-Better-IAM: 1` header, and a `{ data }` or `{ error: { code, message } }` envelope. The SDK handles this format. Cookie-bearing requests require an exact trusted Origin. Root bootstrap, recovery, raw storage, cryptographic helpers, and session-issuance primitives are never HTTP endpoints.

Client-side permission results are advisory. Enforce authorization on the server immediately before performing the protected operation, with resource ownership loaded from trusted storage.

## Package imports

| Import                        | Purpose                                              |
| ----------------------------- | ---------------------------------------------------- |
| `better-iam`                  | Main factory and policy helpers                      |
| `better-iam/core`             | Domain, policy, adapter, and plugin contracts        |
| `better-iam/auth`             | Authentication primitives for trusted integrations   |
| `better-iam/auth/templates`   | Native-free email/SMS rendering for outbox messages  |
| `better-iam/server`           | IAM services and handlers                            |
| `better-iam/client`           | Browser-safe typed SDK                               |
| `better-iam/client/passkeys`  | Browser WebAuthn ceremony helpers                    |
| `better-iam/react`            | React provider, hooks, and `Can` component           |
| `better-iam/next`             | Next.js App Router guards, server client, helpers    |
| `better-iam/next/edge`        | Edge-safe middleware, assertion, webhook helpers     |
| `better-iam/nestjs`           | NestJS module, guards, decorators, and HTTP mount    |
| `better-iam/vue`              | Vue plugin, composables, and `IamCan` component      |
| `better-iam/client/session`   | Framework-agnostic session store                     |
| `better-iam/svelte/kit`       | SvelteKit `handle`, `locals.iam`, load/action guards |
| `better-iam/svelte`           | Svelte 4/5 stores for sessions and decisions         |
| `better-iam/express`          | Express/Connect API mount, `req.iam`, route guards   |
| `better-iam/hono`             | Hono middleware, `c.get('iam')`, route guards        |
| `better-iam/fastify`          | Fastify plugin, `request.iam`, `preHandler` guards   |
| `better-iam/react-router`     | React Router middleware, loader/action guards        |
| `better-iam/middleware`       | Framework-neutral request helpers for other servers  |
| `better-iam/mcp`              | MCP server gate: tool authorization for agents       |
| `better-iam/a2a`              | A2A: attested agent cards, verification, server gate |
| `better-iam/session-tokens`   | Runtime-neutral offline verifier for session JWTs    |
| `@better-iam/nuxt`            | Nuxt module (install directly; not in umbrella)      |
| `@better-iam/nuxt/h3`         | h3 / Nitro server helpers                            |
| `better-iam/projects`         | Reference tenant-scoped Projects plugin              |
| `better-iam/adapter-sqlite`   | SQLite storage                                       |
| `better-iam/adapter-libsql`   | libSQL storage: local files, Turso, sqld             |
| `better-iam/adapter-postgres` | PostgreSQL storage                                   |
| `better-iam/oauth`            | OAuth sign-in and OAuth/OIDC provider                |
| `better-iam/saml`             | SAML service provider                                |
| `better-iam/scim`             | SCIM provisioning server                             |

## Operational defaults

One installation root has universal authority only through the protected root-administrator capability and an authenticated MFA session. Ordinary root-tenant accounts do not inherit that capability. Customers cannot create cross-tenant trust.

Self-registration is disabled by default. Delivery-dependent features require callbacks. Organization creation sends an encrypted-outbox owner invitation and exposes no invitation secret to its creator. Tenant identities remain separate even when accounts are explicitly linked.

The SQL adapters (SQLite, libSQL, PostgreSQL) serialize IAM write transactions. This favors consistent authorization and revocation in the initial release; large installations should measure transaction latency and record-scan costs. Product data remains in the product's own database; Better IAM does not automatically make a separate product database write atomic with an authorization check.

## Console application

[apps/console](apps/console/README.md) is a Next.js application on top of the library: an **administration panel** (`/admin`) for root administrators to run the installation and every organization, and a **cloud console** (`/cloud`) where each organization is a multi-user account with workspaces, members, roles, groups, policies, resource types, service credentials, and account settings. It uses the same `iam.api.*` services from server components and the typed browser client, mounts `iam.handler` at `/api/iam`, and enforces page access with `iam.require`.

```sh
pnpm --filter @better-iam/console migrate
pnpm --filter @better-iam/console bootstrap   # BETTER_IAM_ROOT_EMAIL / BETTER_IAM_ROOT_PASSWORD
pnpm --filter @better-iam/console dev
```

## Documentation

- [Architecture and public interfaces](docs/architecture.md)
- [Authentication guide: sign-in, MFA, sessions, recovery, tenant policies](docs/authentication.md)
- [Temporary credentials: AssumeRole, session tokens, session JWTs, web-identity federation](docs/temporary-credentials.md)
- [Recipes: sharing, reviews, assertions, audit archives, limits, and more](docs/recipes.md)
- [Privileged access: just-in-time roles, approvals, windows, expiry, offboarding, reports, configuration as code](docs/privileged-access.md)
- [Access governance: role mining, usage and right-sizing, change previews, invariants, terms of use, self-service access](docs/governance.md)
- [Feature flags: platform and tenant flags, targets, overrides, rollouts, kill switches](docs/feature-flags.md)
- [Onboarding: member checklists and tenant setup at platform, organization, and project level](docs/onboarding.md)
- [Teams and departments: nested teams with maintainers and join requests, the org chart, department heads](docs/teams-and-departments.md)
- [AI agents: agent accounts, sponsors, delegation on people's behalf, MCP tool authorization](docs/agents.md)
- [Inference: model access policies, provider key vault, budgets, metering, and the model gateway](docs/inference.md)
- [Billing: usage meters, rate cards, spend by person, team, department and project, budgets, statements](docs/billing.md)
- [API reference: every group, method, and route](docs/api-reference.md)
- [Policies and delegation](docs/policies.md)
- [Events and webhooks](docs/events.md)
- [Security model and root authority](docs/security.md)
- [Protocols and interoperability](docs/protocols.md)
- [Enterprise onboarding: domains, SSO, SCIM in and out, offboarding](docs/enterprise.md)
- [Deployment, migrations, and releases](docs/deployment.md)
- [CLI: configuration discovery, login and profiles, any API method, configuration as code, project commands](docs/cli.md)
- [Adapters and plugins](docs/extensions.md)

Better IAM is released under the [MIT license](LICENSE). Third-party dependencies retain their own licenses. This project does not claim AWS API compatibility, universal edge-runtime support, or external security certification.
