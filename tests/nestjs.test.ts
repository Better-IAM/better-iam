import 'reflect-metadata';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import {
  Controller,
  Get,
  Inject,
  Injectable,
  Module,
  Post,
  Req,
  type INestApplication,
} from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { ExecutionContextHost } from '@nestjs/core/helpers/execution-context-host.js';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { AuditEvent, Identity, IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';
import { createRequire } from 'node:module';
import {
  AssertionClaims,
  Authorize,
  Credentials,
  CurrentIdentity,
  CurrentPrincipal,
  FilterAccessible,
  IamAssertionModule,
  IamGuard,
  IamModule,
  IamService,
  OnIamEvent,
  Public,
  RequireClaims,
  RequireMfa,
  TenantId,
  type IamModuleOptions,
  type IamOptionsFactory,
  type RequestLike,
} from '@better-iam/nestjs';
import { createTestingIam } from '@better-iam/nestjs/testing';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
const apps: INestApplication[] = [];
afterEach(async () => {
  for (const app of apps.splice(0)) await app.close();
  for (const database of databases.splice(0)) await database.close();
});

async function tenantFixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'nestjs-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: {
      mode: 'tenant-defined',
      resourceTypes: { document: { managed: true, actions: ['documents:read'] } },
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    { parentId: root.tenant.id, name: 'Acme', type: 'organization', ownerEmail: 'owner@acme.test' },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  await iam.api.identities.create(ownerCredential, {
    tenantId,
    email: 'alice@acme.test',
    name: 'Alice',
    password: 'a strong alice password',
  });
  const alice = await iam.api.auth.signIn({
    tenantId,
    email: 'alice@acme.test',
    password: 'a strong alice password',
  });
  if (!('token' in alice)) throw new Error('Unexpected MFA');
  const aliceId = (await iam.api.auth.getSession({ token: alice.token })).identity.id;
  return { iam, tenantId, owner, ownerCredential, alice, aliceId, rootTenantId: root.tenant.id };
}

type Fixture = Awaited<ReturnType<typeof tenantFixture>>;

function controllers() {
  @Controller()
  class ProjectsController {
    constructor(@Inject(IamService) private readonly iamService: IamService) {}

    @Get('me')
    me(@CurrentIdentity() identity: Identity) {
      return { id: identity.id, email: identity.email };
    }

    @Public()
    @Get('status')
    status(@CurrentPrincipal() principal: { identity: Identity } | null) {
      return { signedIn: principal !== null, id: principal?.identity.id ?? null };
    }

    @Authorize('iam:identities:read')
    @Get('tenants/:tenantId/members')
    members(@TenantId() tenantId: string) {
      return { tenantId };
    }

    @Authorize('iam:identities:read', { resource: { type: 'iam', id: { param: 'tenantId' } } })
    @Post('tenants/:tenantId/things')
    createThing(@TenantId() tenantId: string) {
      return { created: true, tenantId };
    }

    @RequireMfa()
    @Get('sensitive')
    sensitive() {
      return { ok: true };
    }

    @Credentials('api-key')
    @Get('machine')
    machine(@CurrentPrincipal() principal: { session: { kind: string } }) {
      return { kind: principal.session.kind };
    }

    @Get('tenants/:tenantId/can')
    async can(@Req() request: RequestLike & { params: { tenantId: string } }) {
      return this.iamService.can(request, {
        tenantId: request.params.tenantId,
        checks: [{ action: 'iam:identities:read' }, { action: 'iam:tenants:delete' }],
      });
    }

    @Public()
    @Get('ready')
    ready() {
      return this.iamService.health();
    }

    @FilterAccessible('documents:read', { type: 'document' })
    @Get('tenants/:tenantId/documents')
    documents() {
      return [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'unregistered' }];
    }

    @FilterAccessible<{ key: string }>('documents:read', {
      type: 'document',
      path: 'items',
      id: (item) => item.key,
    })
    @Get('tenants/:tenantId/documents/page')
    documentPage() {
      return { items: [{ key: 'a' }, { key: 'b' }, { key: 'c' }], next: null };
    }

    @Get('tenants/:tenantId/require')
    async require(@Req() request: RequestLike & { params: { tenantId: string } }) {
      await this.iamService.require(request, {
        tenantId: request.params.tenantId,
        action: 'iam:identities:read',
        resource: { type: 'iam', id: request.params.tenantId },
      });
      return { ok: true };
    }
  }
  return ProjectsController;
}

async function listen(app: INestApplication): Promise<string> {
  apps.push(app);
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function expressApp(f: Pick<Fixture, 'iam'>, providers: unknown[] = []) {
  @Module({
    imports: [IamModule.forRoot({ iam: f.iam, guard: true, mount: true })],
    controllers: [controllers()],
    providers: providers as never[],
  })
  class AppModule {}
  const app = await NestFactory.create(AppModule, { logger: false });
  return { app, url: await listen(app) };
}

const json = (response: Response) => response.json() as Promise<Record<string, unknown>>;

describe('@better-iam/nestjs', () => {
  it('guards routes, resolves principals, and enforces @Authorize rules on Express', async () => {
    const f = await tenantFixture();
    const { url } = await expressApp(f);
    const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

    const anonymous = await fetch(`${url}/me`);
    expect(anonymous.status).toBe(401);
    expect(await json(anonymous)).toEqual({
      error: { code: 'UNAUTHENTICATED', message: expect.any(String) },
    });
    expect(await json(await fetch(`${url}/status`))).toEqual({ signedIn: false, id: null });
    // An invalid credential on a public route is ignored rather than rejected.
    expect(
      await json(await fetch(`${url}/status`, { headers: bearer('not-a-real-token') })),
    ).toEqual({ signedIn: false, id: null });
    expect(
      await json(await fetch(`${url}/status`, { headers: bearer(f.alice.token) })),
    ).toMatchObject({ signedIn: true });

    const me = await fetch(`${url}/me`, { headers: bearer(f.alice.token) });
    expect(me.status).toBe(200);
    expect(await json(me)).toMatchObject({ email: 'alice@acme.test' });

    // Tenant comes from the route parameter; Alice has no grants, the owner does.
    const denied = await fetch(`${url}/tenants/${f.tenantId}/members`, {
      headers: bearer(f.alice.token),
    });
    expect(denied.status).toBe(403);
    expect(await json(denied)).toMatchObject({ error: { code: 'ACCESS_DENIED' } });
    const allowed = await fetch(`${url}/tenants/${f.tenantId}/members`, {
      headers: bearer(f.owner.token),
    });
    expect(allowed.status).toBe(200);
    expect(await json(allowed)).toEqual({ tenantId: f.tenantId });

    // Session-level requirements.
    const mfa = await fetch(`${url}/sensitive`, { headers: bearer(f.owner.token) });
    expect(mfa.status).toBe(403);
    expect(await json(mfa)).toMatchObject({ error: { code: 'MFA_REQUIRED' } });
    const machine = await fetch(`${url}/machine`, { headers: bearer(f.owner.token) });
    expect(machine.status).toBe(403);
    expect(await json(machine)).toMatchObject({ error: { code: 'CREDENTIAL_NOT_ALLOWED' } });
    const service = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deployer',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: service.id,
    });
    const machineOk = await fetch(`${url}/machine`, { headers: bearer(key.token) });
    expect(machineOk.status).toBe(200);
    expect(await json(machineOk)).toEqual({ kind: 'api-key' });

    // IamService: advisory batches and IamErrors rendered by the exception filter.
    expect(
      await json(
        await fetch(`${url}/tenants/${f.tenantId}/can`, { headers: bearer(f.owner.token) }),
      ),
    ).toEqual({
      [`iam:identities:read@iam/${f.tenantId}`]: true,
      [`iam:tenants:delete@iam/${f.tenantId}`]: expect.any(Boolean),
    });
    const required = await fetch(`${url}/tenants/${f.tenantId}/require`, {
      headers: bearer(f.alice.token),
    });
    expect(required.status).toBe(403);
    expect(required.headers.get('cache-control')).toBe('no-store');
    expect(await json(required)).toMatchObject({ error: { code: 'ACCESS_DENIED' } });
  });

  it('mounts the IAM HTTP API inside Nest and protects cookie sessions from cross-site posts', async () => {
    const f = await tenantFixture();
    const { url } = await expressApp(f);
    const health = await fetch(`${url}/api/iam/health`);
    expect(health.status).toBe(200);
    expect(await json(health)).toMatchObject({ status: 'ok' });

    // Nest's JSON parser consumes the body first; the mount re-serialises it for the IAM handler.
    const signIn = await fetch(`${url}/api/iam/auth/signIn`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
      body: JSON.stringify({
        tenantId: f.tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      }),
    });
    expect(signIn.status).toBe(200);
    const cookie = signIn.headers.getSetCookie()[0]!.split(';')[0]!;
    expect(cookie).toMatch(/^better-iam\.session=/);
    const csrf = await fetch(`${url}/api/iam/auth/getSession`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: '{}',
    });
    expect(csrf.status).toBe(403);

    const me = await fetch(`${url}/me`, { headers: { cookie } });
    expect(await json(me)).toMatchObject({ email: 'owner@acme.test' });
    const things = `${url}/tenants/${f.tenantId}/things`;
    const crossSite = await fetch(things, {
      method: 'POST',
      headers: { cookie, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
    });
    expect(crossSite.status).toBe(403);
    expect(await json(crossSite)).toMatchObject({ error: { code: 'CSRF_REJECTED' } });
    const sameOrigin = await fetch(things, {
      method: 'POST',
      headers: { cookie, origin: url },
    });
    expect(sameOrigin.status).toBe(201);
    expect(await json(sameOrigin)).toEqual({ created: true, tenantId: f.tenantId });
    // Bearer credentials are never ambient, so they skip the origin check.
    const bearer = await fetch(things, {
      method: 'POST',
      headers: { authorization: `Bearer ${f.owner.token}`, origin: 'https://evil.example' },
    });
    expect(bearer.status).toBe(201);
    // The scheme is case-insensitive (RFC 9110), as it is for the server itself; a lowercase bearer is still a bearer.
    const lowercase = await fetch(things, {
      method: 'POST',
      headers: {
        authorization: `bearer ${f.owner.token}`,
        origin: 'https://evil.example',
        'sec-fetch-site': 'cross-site',
      },
    });
    expect(lowercase.status).toBe(201);
    expect(await json(lowercase)).toEqual({ created: true, tenantId: f.tenantId });
    // Session tokens are bearer credentials too, whatever the scheme's case.
    const sessionToken = await f.iam.api.sts.getSessionToken(f.ownerCredential);
    const derived = await fetch(things, {
      method: 'POST',
      headers: { authorization: `BEARER ${sessionToken.token}`, origin: 'https://evil.example' },
    });
    expect(derived.status).toBe(201);
  });

  it('delivers audit events to @OnIamEvent handlers', async () => {
    const f = await tenantFixture();
    const received: AuditEvent[] = [];
    @Injectable()
    class AuditListener {
      @OnIamEvent('iam:identities:*')
      onIdentity(event: AuditEvent) {
        received.push(event);
      }
    }
    const { app } = await expressApp(f, [AuditListener]);
    await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      name: 'Bob',
      password: 'a strong bob password',
    });
    await f.iam.events.dispatch();
    expect(received.some((event) => event.action === 'iam:identities:create')).toBe(true);
    expect(received.every((event) => event.action.startsWith('iam:identities:'))).toBe(true);
    await app.close();
    apps.splice(apps.indexOf(app), 1);
    const count = received.length;
    await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId });
    await f.iam.events.dispatch();
    expect(received.length).toBe(count);
  });

  it('runs on Fastify with forRootAsync', async () => {
    const f = await tenantFixture();
    @Module({
      imports: [
        IamModule.forRootAsync({
          guard: true,
          mount: true,
          useFactory: async () => ({ iam: f.iam, tenant: { header: 'x-tenant' } }),
        }),
      ],
      controllers: [controllers()],
    })
    class FastifyModule {}
    const app = await NestFactory.create(FastifyModule, new FastifyAdapter(), { logger: false });
    const url = await listen(app);
    const signIn = await fetch(`${url}/api/iam/auth/signIn`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
      body: JSON.stringify({
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        password: 'a strong alice password',
      }),
    });
    expect(signIn.status).toBe(200);
    const token = ((await json(signIn)).data as { token: string }).token;
    expect(
      await json(await fetch(`${url}/me`, { headers: { authorization: `Bearer ${token}` } })),
    ).toMatchObject({ email: 'alice@acme.test' });
    // The module resolver reads the tenant from `x-tenant`; the rule itself names no tenant.
    const members = await fetch(`${url}/tenants/ignored/members`, {
      headers: { authorization: `Bearer ${f.owner.token}`, 'x-tenant': f.tenantId },
    });
    expect(members.status).toBe(200);
    expect(await json(members)).toEqual({ tenantId: f.tenantId });
    expect((await fetch(`${url}/me`)).status).toBe(401);
  });

  it('verifies stateless assertions in downstream services', async () => {
    const f = await tenantFixture();
    const issued = await f.iam.api.assertions.issue(f.ownerCredential, {
      tenantId: f.tenantId,
      audience: 'billing',
      claims: { plan: 'pro' },
    });
    const other = await f.iam.api.assertions.issue(f.ownerCredential, {
      tenantId: f.tenantId,
      audience: 'reports',
    });
    @Controller('invoices')
    class InvoicesController {
      @Get()
      list(@AssertionClaims() claims: { sub: string; tid: string; ext?: unknown }) {
        return { sub: claims.sub, tid: claims.tid, ext: claims.ext };
      }
      @RequireClaims({ roles: ['no-such-role'] })
      @Get('admin')
      admin() {
        return { ok: true };
      }
      @RequireClaims({ kinds: ['user'] })
      @Get('users')
      users() {
        return { ok: true };
      }
    }
    @Module({
      imports: [
        IamAssertionModule.forRoot({
          key: f.iam.assertionKey(),
          audience: 'billing',
          issuer: 'http://localhost:3000',
          guard: true,
        }),
      ],
      controllers: [InvoicesController],
    })
    class BillingModule {}
    const app = await NestFactory.create(BillingModule, { logger: false });
    const url = await listen(app);
    const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });
    const ok = await fetch(`${url}/invoices`, bearer(issued.token));
    expect(ok.status).toBe(200);
    expect(await json(ok)).toEqual({
      sub: f.owner.identity.id,
      tid: f.tenantId,
      ext: { plan: 'pro' },
    });
    const wrongAudience = await fetch(`${url}/invoices`, bearer(other.token));
    expect(wrongAudience.status).toBe(401);
    expect(await json(wrongAudience)).toMatchObject({ error: { code: 'INVALID_ASSERTION' } });
    expect((await fetch(`${url}/invoices`)).status).toBe(401);
    expect((await fetch(`${url}/invoices/admin`, bearer(issued.token))).status).toBe(403);
    expect((await fetch(`${url}/invoices/users`, bearer(issued.token))).status).toBe(200);
    expect(() => IamAssertionModule.forRoot({ key: 'short', audience: 'billing' })).toThrow(
      'assertion key',
    );
    // While the deployment secret rotates, the module takes the list from iam.assertionKeys().
    expect(() =>
      IamAssertionModule.forRoot({
        key: [f.iam.assertionKey(), 'a'.repeat(64)],
        audience: 'billing',
      }),
    ).not.toThrow();
    expect(() =>
      IamAssertionModule.forRoot({ key: [f.iam.assertionKey(), 'short'], audience: 'billing' }),
    ).toThrow('assertion key');
    expect(() => IamAssertionModule.forRoot({ key: [], audience: 'billing' })).toThrow(
      'assertion key',
    );
  });

  it('filters list responses to accessible resources and reports readiness', async () => {
    const f = await tenantFixture();
    await f.iam.api.resources.registerMany(f.ownerCredential, {
      tenantId: f.tenantId,
      resources: ['a', 'b', 'c'].map((id) => ({ type: 'document', id })),
    });
    const reader = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Some documents',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/a', 'document/c'],
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: f.aliceId,
    });
    const { url } = await expressApp(f);
    const as = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });
    const documents = `${url}/tenants/${f.tenantId}/documents`;
    expect(await (await fetch(documents, as(f.alice.token))).json()).toEqual([
      { id: 'a' },
      { id: 'c' },
    ]);
    // Unregistered items are never accessible, even to the owner.
    expect(await (await fetch(documents, as(f.owner.token))).json()).toEqual([
      { id: 'a' },
      { id: 'b' },
      { id: 'c' },
    ]);
    expect(await (await fetch(`${documents}/page`, as(f.alice.token))).json()).toEqual({
      items: [{ key: 'a' }, { key: 'c' }],
      next: null,
    });
    const ready = await fetch(`${url}/ready`);
    expect(await ready.json()).toEqual({ status: 'up', latencyMs: expect.any(Number) });
  });

  it('builds options with forRootAsync useClass and useExisting', async () => {
    const f = await tenantFixture();
    @Injectable()
    class IamConfig implements IamOptionsFactory {
      createIamOptions(): IamModuleOptions {
        return { iam: f.iam, csrf: false };
      }
    }
    @Module({ providers: [IamConfig], exports: [IamConfig] })
    class ConfigModule {}
    for (const imports of [
      [IamModule.forRootAsync({ guard: true, useClass: IamConfig })],
      [IamModule.forRootAsync({ guard: true, imports: [ConfigModule], useExisting: IamConfig })],
    ]) {
      @Module({ imports, controllers: [controllers()] })
      class AsyncModule {}
      const app = await NestFactory.create(AsyncModule, { logger: false });
      const url = await listen(app);
      expect((await fetch(`${url}/me`)).status).toBe(401);
      expect(
        (await fetch(`${url}/me`, { headers: { authorization: `Bearer ${f.alice.token}` } }))
          .status,
      ).toBe(200);
    }
    expect(() => IamModule.forRootAsync({})).toThrow('useFactory, useClass, or useExisting');
  });

  it('authenticates GraphQL and WebSocket contexts', async () => {
    const f = await tenantFixture();
    const guard = new IamGuard(new Reflector(), { iam: f.iam });
    class Resolver {
      viewer() {}
      @Authorize('iam:identities:read')
      members() {}
      @Authorize('iam:identities:read', {
        tenant: { arg: 'tenantId' },
        resource: { type: 'iam', id: { arg: 'tenantId' } },
      })
      scoped() {}
    }
    const context = (type: string, args: unknown[], handler: () => void) => {
      const host = new ExecutionContextHost(args, Resolver, handler);
      host.setType(type);
      return host;
    };
    const principalParam = (host: ExecutionContextHost) => {
      // Reads what @CurrentPrincipal() would return, through the guard's per-request state.
      const [factory] = Object.values(
        Reflect.getMetadata('__routeArguments__', Probe, 'probe') as Record<
          string,
          { factory: (data: unknown, context: ExecutionContextHost) => unknown }
        >,
      );
      return factory!.factory(undefined, host) as { identity: { id: string } } | null;
    };
    class Probe {
      probe(@CurrentPrincipal() _principal: unknown) {}
    }
    const gqlRequest = { headers: { authorization: `Bearer ${f.alice.token}` } };
    const gql = context('graphql', [{}, {}, { req: gqlRequest }, {}], Resolver.prototype.viewer);
    expect(await guard.canActivate(gql)).toBe(true);
    expect(principalParam(gql)?.identity.id).toBe(f.aliceId);
    await expect(
      guard.canActivate(
        context(
          'graphql',
          [{}, { tenantId: f.tenantId }, { req: gqlRequest }, {}],
          Resolver.prototype.members,
        ),
      ),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      guard.canActivate(
        context('graphql', [{}, {}, { req: { headers: {} } }, {}], Resolver.prototype.viewer),
      ),
    ).rejects.toMatchObject({ status: 401 });

    // Resolver arguments feed { arg } sources: the owner is allowed in their tenant, not in another.
    const ownerRequest = { headers: { authorization: `Bearer ${f.owner.token}` } };
    expect(
      await guard.canActivate(
        context(
          'graphql',
          [{}, { tenantId: f.tenantId }, { req: ownerRequest }, {}],
          Resolver.prototype.scoped,
        ),
      ),
    ).toBe(true);
    await expect(
      guard.canActivate(
        context(
          'graphql',
          [{}, { tenantId: f.rootTenantId }, { req: { ...ownerRequest } }, {}],
          Resolver.prototype.scoped,
        ),
      ),
    ).rejects.toMatchObject({ status: 403 });

    // socket.io: the handshake carries the credential, and each message is authorised separately.
    const client = {
      handshake: { headers: { authorization: `Bearer ${f.owner.token}` } },
      emit() {},
    };
    const message = { tenantId: f.tenantId };
    const ws = context('ws', [client, message], Resolver.prototype.members);
    expect(await guard.canActivate(ws)).toBe(true);
    expect(principalParam(ws)?.identity.id).toBe(f.owner.identity.id);
    await f.iam.api.auth.signOut({ token: f.owner.token });
    await expect(
      guard.canActivate(
        context('ws', [client, { tenantId: f.tenantId }], Resolver.prototype.members),
      ),
    ).rejects.toMatchObject({ status: 401 });
    // Transports without HTTP credentials are refused unless the handler is public.
    await expect(
      guard.canActivate(context('rpc', [{}, {}], Resolver.prototype.viewer)),
    ).rejects.toMatchObject({ status: 401 });
  });

  it('tests Nest applications without a database through createTestingIam', async () => {
    const received: string[] = [];
    @Injectable()
    class Listener {
      @OnIamEvent('identity:*')
      on(event: AuditEvent) {
        received.push(`${event.action}@${event.tenantId}`);
      }
    }
    const iam = createTestingIam({
      principals: {
        alice: { identity: { email: 'alice@example.test', tenantId: 't1' } },
        admin: { identity: { tenantId: 't1' }, session: { mfa: true } },
        bot: { identity: { kind: 'service', tenantId: 't1' } },
      },
      decide: ({ principal, action, resource }) =>
        principal.session.mfa ||
        (action === 'documents:read' &&
          resource.id === 'a' &&
          principal.identity.id === 'identity_alice'),
      resources: { document: ['a', 'b', 'c'] },
    });
    const moduleRef = await Test.createTestingModule({
      imports: [IamModule.forRoot({ iam, guard: true })],
      controllers: [controllers()],
      providers: [Listener],
    }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    const url = await listen(app);
    const as = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

    expect((await fetch(`${url}/me`)).status).toBe(401);
    expect((await fetch(`${url}/me`, as('mallory'))).status).toBe(401);
    expect(await json(await fetch(`${url}/me`, as('alice')))).toEqual({
      id: 'identity_alice',
      email: 'alice@example.test',
    });
    expect((await fetch(`${url}/tenants/t1/members`, as('alice'))).status).toBe(403);
    expect((await fetch(`${url}/tenants/t1/members`, as('admin'))).status).toBe(200);
    expect(iam.decisions.at(-1)).toMatchObject({
      tenantId: 't1',
      action: 'iam:identities:read',
      resource: { type: 'iam', id: 't1' },
      allowed: true,
    });
    expect((await fetch(`${url}/sensitive`, as('alice'))).status).toBe(403);
    expect((await fetch(`${url}/sensitive`, as('admin'))).status).toBe(200);
    expect(await json(await fetch(`${url}/machine`, as('bot')))).toEqual({ kind: 'api-key' });
    expect(await (await fetch(`${url}/tenants/t1/documents`, as('alice'))).json()).toEqual([
      { id: 'a' },
    ]);
    expect(await (await fetch(`${url}/tenants/t1/documents`, as('admin'))).json()).toEqual([
      { id: 'a' },
      { id: 'b' },
      { id: 'c' },
    ]);
    await iam.emit({ action: 'identity:create', tenantId: 't1' });
    await iam.emit({ action: 'tenant:create' });
    expect(received).toEqual(['identity:create@t1']);
    expect(iam.principal('bot').session.kind).toBe('api-key');
  });
});
