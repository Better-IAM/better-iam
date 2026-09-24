import 'reflect-metadata';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { Controller, Get, Module, Post, type INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
  Authorize,
  Credentials,
  IamAssertionModule,
  IamModule,
  Public,
  RequireClaims,
  RequireMfa,
} from '@better-iam/nestjs';
import { closeFixtures, organizationFixture } from './support/organization.js';

const apps: INestApplication[] = [];
afterEach(async () => {
  for (const app of apps.splice(0)) await app.close();
  await closeFixtures();
});
async function listen(app: INestApplication): Promise<string> {
  apps.push(app);
  await app.listen(0, '127.0.0.1');
  return `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
}

/**
 * Security review regressions (session e15e8e): `@Public()` must not turn the other guard metadata into no-ops for
 * anonymous callers.
 */
describe('NestJS guards on @Public() handlers', () => {
  it('refuses anonymous and invalid credentials where rules still apply, and keeps plain public routes open', async () => {
    const f = await organizationFixture();
    @Public()
    @Controller()
    class OpenController {
      @Get('open')
      open() {
        return { ok: true };
      }
      @Authorize('iam:tenants:delete')
      @Post('purge')
      purge() {
        return { purged: true };
      }
      @RequireMfa()
      @Get('mfa')
      mfa() {
        return { ok: true };
      }
      @Credentials('api-key')
      @Get('machine')
      machine() {
        return { ok: true };
      }
    }
    @Module({
      imports: [IamModule.forRoot({ iam: f.iam, guard: true })],
      controllers: [OpenController],
    })
    class AppModule {}
    const url = await listen(await NestFactory.create(AppModule, { logger: false }));

    expect((await fetch(`${url}/open`)).status).toBe(200);
    expect((await fetch(`${url}/open`, { headers: { authorization: 'Bearer junk' } })).status).toBe(
      200,
    );
    for (const [path, method] of [
      ['purge', 'POST'],
      ['mfa', 'GET'],
      ['machine', 'GET'],
    ] as const) {
      expect((await fetch(`${url}/${path}`, { method })).status, path).toBe(401);
      expect(
        (await fetch(`${url}/${path}`, { method, headers: { authorization: 'Bearer junk' } }))
          .status,
        path,
      ).toBe(401);
    }
    // A signed-in member without the permission is still denied, as before.
    await f.member('bob');
    const bob = await f.signIn('bob');
    expect(
      (
        await fetch(`${url}/purge`, {
          method: 'POST',
          headers: { authorization: `Bearer ${bob.token}` },
        })
      ).status,
    ).toBe(403);
  });

  it('applies @RequireClaims to public assertion handlers and accepts a lowercase bearer scheme', async () => {
    const f = await organizationFixture();
    @Public()
    @Controller()
    class ReportsController {
      @Get('reports')
      list() {
        return { ok: true };
      }
      @RequireClaims({ mfa: true })
      @Get('reports/admin')
      admin() {
        return { ok: true };
      }
    }
    @Module({
      imports: [
        IamAssertionModule.forRoot({ key: f.iam.assertionKey(), audience: 'reports', guard: true }),
      ],
      controllers: [ReportsController],
    })
    class AppModule {}
    const url = await listen(await NestFactory.create(AppModule, { logger: false }));
    expect((await fetch(`${url}/reports`)).status).toBe(200);
    expect((await fetch(`${url}/reports/admin`)).status).toBe(401);
    expect(
      (await fetch(`${url}/reports/admin`, { headers: { authorization: 'Bearer junk.a.b' } }))
        .status,
    ).toBe(401);
    const owner = await f.ownerSignIn();
    const issued = await f.iam.api.assertions.issue(owner, {
      tenantId: f.tenantId,
      audience: 'reports',
    });
    // The owner's session has no MFA: the claim requirement refuses it (403), with either scheme spelling.
    for (const scheme of ['Bearer', 'bearer'])
      expect(
        (
          await fetch(`${url}/reports/admin`, {
            headers: { authorization: `${scheme} ${issued.token}` },
          })
        ).status,
        scheme,
      ).toBe(403);
  });
});
