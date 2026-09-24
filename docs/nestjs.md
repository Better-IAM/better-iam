# NestJS

`@better-iam/nestjs` (also `better-iam/nestjs`) integrates Better IAM with NestJS 11 and 12 on Express or Fastify. The [package README](../packages/nestjs/README.md) has the API tour. This guide explains how requests flow through the integration, what each piece guarantees, and patterns for multi-tenant apps, GraphQL, gateways, microservices, and tests. The [example app](../examples/nestjs/README.md) runs all of it.

## Layout of an application

```
src/iam.ts            betterIam({ ... })                        the IAM instance (database, argon2)
src/app.module.ts     IamModule.forRoot({ iam, guard, mount })  guard, filter, service, served IAM API
src/*.controller.ts   @Authorize / @Public / @CurrentIdentity   declarative enforcement per route
src/*.listener.ts     @OnIamEvent('identity:*')                 reactions to committed audit events
src/main.ts           NestFactory.create(App, { rawBody: true })
```

`IamModule` is global by default, so any module can inject `IamService` without re-importing it. `forRootAsync` builds the options from other providers with `useFactory` + `inject`, `useClass`, or `useExisting` (an `IamOptionsFactory`). The switches that shape the module graph (`guard`, `mount`, `filter`, `global`) are static arguments in both forms.

## What the guard does, in order

1. **Find the credential.** HTTP uses the request (Express or Fastify). GraphQL uses `context.req`, `context.request`, or `context.reply.request` (Apollo and Mercurius). WebSocket gateways use the socket.io handshake (`client.handshake`, `client.request`). Other transports have no HTTP credential and are refused unless the handler is `@Public()`.
2. **Authenticate** with `iam.authenticate`, which accepts session cookies, bearer session tokens, API keys, and assumed-role credentials. On a `@Public()` handler, a missing or invalid credential yields a `null` principal instead of an error, unless the handler or its class also carries `@Credentials`, `@RequireMfa` or `@Authorize`: those always need a principal, so an anonymous caller gets `401 UNAUTHENTICATED` rather than skipping them. The result is stored per request (per message for gateways) for the parameter decorators and later guards.
3. **CSRF** (HTTP and GraphQL over HTTP): cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` requests must come from the request's own host (`Origin` or `Sec-Fetch-Site: same-origin`) or from `csrf.trustedOrigins`. Bearer credentials skip this check because browsers never attach them implicitly.
4. **Credential kind and MFA:** `@Credentials('api-key')` and `@RequireMfa()`.
5. **Authorization:** every `@Authorize` rule on the class, then on the method, through `iam.authorize`. Each rule is a separate, recorded decision, so denials and root overrides are audited exactly as elsewhere. The first denial stops the request.

| Failure                            | Status | `error.code`                                          |
| ---------------------------------- | ------ | ----------------------------------------------------- |
| no credential, expired, revoked    | 401    | `UNAUTHENTICATED`                                     |
| step-up required by tenant policy  | 403    | `MFA_REQUIRED`                                        |
| `@RequireMfa()` on a non-MFA login | 403    | `MFA_REQUIRED`                                        |
| `@Credentials()` mismatch          | 403    | `CREDENTIAL_NOT_ALLOWED`                              |
| cross-site cookie request          | 403    | `CSRF_REJECTED`                                       |
| any rule denies                    | 403    | `ACCESS_DENIED`                                       |
| missing resource id for a rule     | 400    | `INVALID_INPUT`                                       |
| inactive tenant, rate limits, ...  | server | the server's code (`TENANT_INACTIVE`, `RATE_LIMITED`) |

Guard failures are `HttpException`s with the IAM `{ error: { code, message } }` body, so they render correctly with or without `IamExceptionFilter`. The filter covers `IamError`s thrown later, inside handlers and providers.

Temporary credentials need no extra setup: `iam.authenticate` also accepts session tokens from `sts.getSessionToken` and IAM-signed session JWTs (`format: 'jwt'`), and the CSRF step recognizes the bearer scheme case-insensitively (`bearer …` skips it as `Bearer …` does). `CredentialKind` follows the server's session kinds, so `@Credentials('user', 'api-key')` keeps role sessions and session tokens out of a controller, and `@Credentials('session-token')` admits them explicitly. Temporary credentials never pass the server's recent-authentication checks. See [temporary credentials](temporary-credentials.md).

## Tenancy patterns

A rule is evaluated in exactly one tenant. The guard resolves it in this order:

1. The rule's own `tenant` source.
2. The module's `tenant` option.
3. The `tenantId` route parameter, then the `x-tenant-id` header.
4. The tenant of the caller's session.

```ts
// Path-scoped APIs: /orgs/:tenantId/projects/:id (the default picks up :tenantId).
@Authorize('projects:read', { resource: { type: 'project', id: { param: 'id' } } })

// Subdomain tenancy, resolved once for the whole app.
IamModule.forRoot({
  iam,
  tenant: async (request) => tenantIdForHost(new Headers(request.headers as HeadersInit).get('host')),
});

// A resource that knows its own tenant: resolve both from your storage.
@Authorize('invoices:approve', {
  tenant: async (request) => (await invoices.get(request.params!.id as string)).tenantId,
  resource: { type: 'invoice', id: { param: 'id' } },
})
```

Resolving the tenant from the request never widens access. The decision still checks that the principal holds a grant in that tenant, and a session from one organization has no grants in another.

## GraphQL and gateways

Resolvers use the same decorators. `{ arg: 'name' }` reads a resolver argument. On a gateway, it reads a field of the incoming message.

```ts
@Resolver(() => Project)
export class ProjectsResolver {
  @Query(() => Project)
  @Authorize('projects:read', {
    tenant: { arg: 'tenantId' },
    resource: { type: 'project', id: { arg: 'id' } },
  })
  project(@Args('tenantId') tenantId: string, @Args('id') id: string) {}
}
```

Gateways authenticate from the handshake but authorize each message separately. The principal is re-resolved for every message, so a revoked session stops working at the next message, not at reconnect. Put `@UseGuards(IamGuard)` on each gateway explicitly. `guard: true` is written for HTTP controllers and resolvers, and whether a global guard also reaches gateways depends on the Nest version and application type.

## List endpoints

`@Authorize` protects one resource. To list resources, either query IAM first or filter afterwards:

- **Query first.** `IamService.listAccessible(request, { tenantId, action, type })` returns the registered resources the caller may act on. Use their `resourceId`s in your database query, which keeps pagination correct.
- **Filter afterwards.** `@FilterAccessible(action, { type })` removes inaccessible items from the handler's result (or `result[path]`). It's simpler to adopt, but a page can come back shorter than requested.

Both use one reverse query per 1000 registered resources, never one decision per item, so the audit log does not fill with denials. Both apply only to managed (registered) resource types. For resources resolved through `resolveResource`, use `IamService.can` with at most 50 checks per call.

## Serving the IAM API from Nest

With `mount: true`, the IAM handler serves `mountPath` (by default the server's `basePath`) as Nest middleware, so the browser client, OAuth/OIDC, SAML, and SCIM mounts share your app's port. The handler keeps its own protections: the `X-Better-IAM` header, exact trusted origins for cookie requests, and body limits. `rawBody: true` in `NestFactory.create` lets form posts (SAML ACS) pass through unchanged. Without it, the mount re-serializes the body Nest has already parsed. Under `setGlobalPrefix`, give `mountPath` relative to the prefix, because Nest prefixes middleware routes. For a custom setup, `createIamRequestHandler(iam)` returns a plain `(req, res, next)` handler for `app.use`.

## Events

`@OnIamEvent(pattern | patterns)` subscribes a provider method to audit events, using the same action globs as webhooks (`identity:*`, `iam:identities:*`). Events are delivered after the transaction commits, at least once. Make handlers idempotent: `event.id` is stable across retries. Delivery happens when something calls `iam.events.dispatch()`. `dispatchIntervalMs` runs it inside the app on a timer, and one run at a time. For multi-instance deployments, dispatch from a single worker and leave the option unset elsewhere.

## Microservices: assertions instead of shared sessions

An API gateway or backend-for-frontend authenticates the user and issues a short-lived assertion for each downstream call:

```ts
const { token } = await this.iam.assertion(request, {
  tenantId,
  audience: 'billing',
  ttlSeconds: 60,
});
await fetch('http://billing/invoices', { headers: { authorization: `Bearer ${token}` } });
```

The billing service runs `IamAssertionModule.forRoot({ key, audience: 'billing', issuer, guard: true })` and never opens the IAM database. It reads claims with `@AssertionClaims()` and narrows access with `@RequireClaims({ roles, groups, mfa, kinds })`. The caller needs `iam:assertions:create` on `iam/billing`, so administrators decide which services each role may call. Keep the TTL short, because the downstream service cannot see revocations before an assertion expires.

A downstream service that should hold only public keys verifies session JWTs instead. The caller obtains one with `format: 'jwt'` and the service's audience (`sts.getSessionToken` or `roles.assume`); the service verifies it offline against the IAM JWKS with a small guard:

```ts
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { createSessionTokenVerifier } from 'better-iam/session-tokens';

const verifier = createSessionTokenVerifier({
  issuer: 'https://iam.example.com/api/iam',
  audience: 'billing',
  jwks: 'https://iam.example.com/api/iam/.well-known/jwks.json',
});

@Injectable()
export class SessionTokenGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    try {
      request.sessionClaims = await verifier.verifyRequest({
        headers: { authorization: request.headers.authorization ?? '' },
      });
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
```

The claims name the identity (`sub`), tenant (`tid`), kind, MFA, and for role sessions the role and trust; they never carry tags or policies. Like assertions, offline verification sees revocation only at `exp`: keep `sts.jwt.maxLifetimeSeconds` short, or call `sts/getCallerIdentity` for sensitive requests.

## Testing

| Level                 | Use                                                                                                                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit / controller e2e | `createTestingIam` from `@better-iam/nestjs/testing`: principals by bearer token, decisions from a callback, a `decisions` log, `emit()` for listeners                                |
| Policy-accurate e2e   | a real `betterIam()` with `sqliteAdapter({ filename: ':memory:' })`. Bootstrap, create a tenant and members through `iam.api`, and sign in to get tokens (see `tests/nestjs.test.ts`) |
| Guards in isolation   | `new IamGuard(new Reflector(), { iam })` with `ExecutionContextHost` from `@nestjs/core/helpers/execution-context-host.js`                                                            |

Library code uses explicit `@Inject()` tokens, so the integration also works in test runners that don't emit decorator metadata (Vitest/esbuild). Your own providers need `emitDecoratorMetadata` or explicit `@Inject()` as usual.
