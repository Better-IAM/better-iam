# @better-iam/nestjs

NestJS integration for Better IAM (Nest 11 and 12, Express or Fastify). It gives you a dynamic module, a guard that authenticates every request, declarative authorization decorators, a request-scoped service, an exception filter, the IAM HTTP API served from your Nest app, audit-event handlers on providers, and assertion verification for downstream services. The [guide](../../docs/nestjs.md) covers request flow, tenancy, GraphQL, gateways, microservices, and testing.

```ts
// app.module.ts
import { Module } from '@nestjs/common';
import { IamModule } from '@better-iam/nestjs';
import { iam } from './iam';

@Module({
  imports: [
    IamModule.forRoot({
      iam, // a betterIam() instance
      guard: true, // every route needs a session unless @Public()
      mount: true, // serve POST /api/iam/* (sign-in, admin API, OAuth/SAML/SCIM mounts) from Nest
      dispatchIntervalMs: 1000, // deliver audit events to @OnIamEvent handlers
    }),
  ],
})
export class AppModule {}
```

`forRootAsync({ imports, inject, useFactory, guard, mount, filter, global })` builds the options from other providers (for example `ConfigService`). It also accepts `useClass` or `useExisting`, which take an `IamOptionsFactory` with `createIamOptions()`. The structural switches (`guard`, `mount`, `filter`, `global`) stay static.

## Guarding routes

```ts
import { Controller, Get, Post, Req } from '@nestjs/common';
import {
  Authorize,
  Credentials,
  CurrentIdentity,
  IamService,
  Public,
  RequireMfa,
  TenantId,
} from '@better-iam/nestjs';

@Controller('tenants/:tenantId/projects')
@Authorize('projects:list') // class rules apply to every handler
export class ProjectsController {
  constructor(private readonly iam: IamService) {}

  @Get(':id')
  @Authorize('projects:read', { resource: { type: 'project', id: { param: 'id' } } })
  read(@CurrentIdentity() me: Identity, @TenantId() tenantId: string) {}

  @Post(':id/archive')
  @RequireMfa()
  @Authorize('projects:archive', { resource: { type: 'project', id: { param: 'id' } } })
  archive() {}

  @Post('sync')
  @Credentials('api-key') // machine callers only
  sync() {}

  @Public()
  @Get('/status')
  status() {}

  @Get()
  async list(@Req() request: Request, @TenantId() tenantId: string) {
    // Reverse queries and advisory UI flags for the actual caller.
    const { resources } = await this.iam.listAccessible(request, {
      tenantId,
      action: 'projects:read',
      type: 'project',
    });
    const flags = await this.iam.can(request, {
      tenantId,
      checks: [{ action: 'projects:create' }],
    });
    return { resources, canCreate: flags[`projects:create@iam/${tenantId}`] };
  }
}
```

- **`@Authorize(action, { resource?, tenant? })`**: every rule on the class and the method must allow. The resource defaults to the tenant (`iam/{tenantId}`). Values come from `{ param }`, `{ query }`, `{ body }`, `{ header }`, `{ arg }` (a GraphQL resolver argument or a field of the WebSocket message), a fixed string, or `(request, principal) => value`. `resource` can also be a function that returns `{ type, id }`.
- **Tenant resolution**: a rule's `tenant` comes first, then the module's `tenant` option, then the `tenantId` route parameter, the `x-tenant-id` header, and finally the caller's session tenant.
- **`@Public()`**: no session is required. A valid credential is still resolved, and invalid ones are ignored.
- **`@RequireMfa()`**: the session must have completed MFA. **`@Credentials(...kinds)`** accepts only `user`, `api-key`, or `role` sessions.
- **Parameter decorators**: `@CurrentPrincipal()`, `@CurrentIdentity()`, `@CurrentSession()` (null on public routes without a credential), and `@TenantId()`.
- **Guard failures**: the body is the IAM server's `{ error: { code, message } }` with its status: 401 `UNAUTHENTICATED`, 403 `ACCESS_DENIED` / `MFA_REQUIRED` / `CREDENTIAL_NOT_ALLOWED` / `CSRF_REJECTED`, and 429 for rate limits.
- **Transports**: the guard supports HTTP (Express and Fastify), GraphQL (`context.req`), and socket.io gateways (the handshake headers, authorised per message). Without `guard: true`, apply it with `@UseGuards(IamGuard)`.

**Filtering lists.** `@FilterAccessible(action, { type, id?, path?, tenant? })` drops the items a caller may not act on from a handler's array response, or from `response[path]`. It uses the `listAccessible` reverse query over the registered resources of a managed type: one query per 1000 resources, not one decision per item, so denials don't flood the audit log. Items that aren't registered are always dropped.

```ts
@Get()
@FilterAccessible('documents:read', { type: 'document' })
findAll() {
  return this.documents.findAll(); // [{ id: 'a' }, { id: 'b' }, ...]
}
```

**Readiness and direct calls.** `IamService.health()` checks the IAM database through the server's `/health` endpoint in process and returns `{ status: 'up' | 'down', latencyMs }`, for a Terminus indicator or a readiness route. `IamService.credential(request)` returns the caller's credential for any `iam.api.*` call.

**CSRF.** Browsers attach session cookies to cross-site form posts. The guard therefore rejects cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` requests whose `Origin` is neither the request host nor listed in `csrf.trustedOrigins`. Bearer tokens and API keys are never ambient, so they skip this check. Set `csrf: false` only when another layer enforces it.

## Errors

`IamExceptionFilter` is registered globally by default (`filter: false` turns it off). It renders `IamError`s thrown in handlers, for example by `IamService.require` or direct `iam.api.*` calls, with their status and code instead of a 500. GraphQL gets an `HttpException`, WebSocket clients get an `exception` event, and RPC callers get an error payload.

## Serving the IAM API

With `mount: true`, the IAM handler runs as Nest middleware at `mountPath`, which defaults to the server's `basePath`. Nest's body parsers have usually consumed the body by the time the middleware runs. The mount uses `rawBody` when the app was created with `NestFactory.create(App, { rawBody: true })`, which is recommended for SAML form posts. Otherwise it re-serializes the parsed body. Under `app.setGlobalPrefix('v1')`, Nest prefixes middleware routes too, so give `mountPath` without the prefix. Without the module, use `app.use('/api/iam', createIamRequestHandler(iam))`.

## Audit events

```ts
@Injectable()
export class Notifications {
  @OnIamEvent(['identity:*', 'iam:identities:create'])
  async onIdentity(event: AuditEvent) {}
}
```

Handlers are subscribed at bootstrap and unsubscribed at shutdown. Delivery happens after commit and at least once, whenever `iam.events.dispatch()` runs. `dispatchIntervalMs` runs it on a timer inside the app. If a separate worker dispatches, leave it unset.

## Testing

`@better-iam/nestjs/testing` exports `createTestingIam`, an in-memory stand-in for a `betterIam()` instance. It uses no database and no password hashing. A bearer token picks the principal, a callback makes every decision, and a map lists the registered resources:

```ts
import { Test } from '@nestjs/testing';
import { IamModule } from '@better-iam/nestjs';
import { createTestingIam } from '@better-iam/nestjs/testing';

const iam = createTestingIam({
  principals: {
    alice: { identity: { email: 'alice@example.test', tenantId: 't1' } },
    admin: { identity: { tenantId: 't1' }, session: { mfa: true } },
    ci: { identity: { kind: 'service', tenantId: 't1' } }, // an API key session
  },
  decide: ({ principal, action, resource }) =>
    principal.session.mfa || (action === 'projects:read' && resource.id === 'apollo'),
  resources: { project: ['apollo', 'gemini'] }, // for listAccessible and @FilterAccessible
});
const moduleRef = await Test.createTestingModule({
  imports: [IamModule.forRoot({ iam, guard: true })],
  controllers: [ProjectsController],
}).compile();
// Requests with `authorization: Bearer alice` now run as Alice.
```

`iam.decisions` records every check with its outcome, and `iam.emit({ action: 'identity:create' })` delivers an event to `@OnIamEvent` handlers. For end-to-end tests against real policies, use a `betterIam()` instance with `sqliteAdapter({ filename: ':memory:' })` instead.

## Downstream services: stateless assertions

A service that receives assertions (`IamService.assertion(request, { tenantId, audience })` on the caller's side) verifies them offline. It needs no database and only the derived key:

```ts
@Module({
  imports: [
    IamAssertionModule.forRoot({
      key: process.env.IAM_ASSERTION_KEY!, // iam.assertionKey()
      audience: 'billing',
      issuer: 'https://iam.example.com',
      guard: true,
    }),
  ],
})
export class BillingModule {}

@Controller('invoices')
export class InvoicesController {
  @Get()
  @RequireClaims({ roles: ['role_billing_admin'], mfa: true })
  list(@AssertionClaims() claims: { sub: string; tid: string; roles: string[] }) {}
}
```

This path imports only `@better-iam/server/assertions`, so the verifying service never loads the IAM server or its native dependencies. The IAM server is never contacted, so a revocation takes effect once the short-lived assertion expires.

License: Apache-2.0.
