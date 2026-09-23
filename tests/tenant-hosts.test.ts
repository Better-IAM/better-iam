import { createServer, request as httpRequest } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type BetterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { renderDeliveryMessage } from '@better-iam/auth';
import { createIamNext } from '@better-iam/next';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const hosts = { patterns: ['{tenant}.localhost:3000'], signInPath: '/login' };

/** POSTs a JSON call to the handler at `url`, as a browser on `origin` would. */
async function post(
  iam: BetterIam,
  url: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) {
  const response = await iam.handler(
    new Request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
      body: JSON.stringify(body),
    }),
  );
  return {
    status: response.status,
    headers: response.headers,
    body: (await response.json()) as {
      data?: Record<string, unknown>;
      error?: { code: string; message: string; location?: string; region?: string };
    },
  };
}

/** A second organization with an alias and an owner session. */
async function organization(f: OrganizationFixture, name: string, slug: string) {
  const created = await f.iam.api.tenants.create(f.rootCredential, {
    parentId: f.root.tenant.id,
    name,
    type: 'organization',
    ownerEmail: `owner@${slug}.test`,
    slug,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return { tenantId: created.tenant.id, credential: { token: owner.token } };
}

async function hostFixture() {
  const f = await organizationFixture({ hosts });
  await f.iam.api.tenants.setSlug(f.rootCredential, { tenantId: f.tenantId, slug: 'acme' });
  await f.member('alice');
  return f;
}

describe('organization sign-in addresses', () => {
  it('validates host patterns when the instance is built', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    const base = {
      database,
      secret: 'tenant-hosts-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    };
    const cases: [object, RegExp][] = [
      [{ patterns: ['signin.localhost'] }, /\{tenant\} exactly once/],
      [{ patterns: ['{tenant}.{tenant}.localhost'] }, /\{tenant\} exactly once/],
      [{ patterns: ['{tenant}.{region}.localhost'] }, /needs the regions option/],
      [{ patterns: ['{tenant}.signin.example.com'] }, /HTTPS baseURL outside localhost/],
      [{ patterns: ['{tenant}'] }, /not a valid hostname template/],
      [{ patterns: ['{tenant}.local_host'] }, /not a valid hostname template/],
      [{ signInPath: 'login' }, /signInPath/],
      [{ cnameTarget: 'not a host' }, /cnameTarget/],
    ];
    for (const [option, message] of cases)
      expect(() => betterIam({ ...base, hosts: option as never })).toThrow(message);
    // Passkeys belong to one domain, so every organization address must sit under the RP ID.
    expect(() =>
      betterIam({
        ...base,
        baseURL: 'https://signin.example.com',
        authentication: { passkeys: { rpID: 'example.com' } },
        hosts: { patterns: ['{tenant}.signin.other.net'] },
      }),
    ).toThrow(/must be under the passkey RP ID example.com/);
    expect(() =>
      betterIam({
        ...base,
        baseURL: 'https://signin.example.com',
        authentication: { passkeys: { rpID: 'example.com' } },
        hosts: { patterns: ['{tenant}.signin.example.com'] },
      }),
    ).not.toThrow();
    await database.close();
  });

  it('signs in on the organization address without a tenant ID, and never into another organization', async () => {
    const f = await hostFixture();
    const globex = await organization(f, 'Globex', 'globex');
    const acmeOrigin = 'http://acme.localhost:3000';
    const signedIn = await post(
      f.iam,
      `${acmeOrigin}/api/iam/auth/signIn`,
      { email: 'alice@acme.test', password: 'a strong alice password' },
      { origin: acmeOrigin },
    );
    expect(signedIn.status).toBe(200);
    expect(signedIn.body.data).toMatchObject({ token: expect.any(String) });
    // The organization's origin is trusted like the deployment's own, and the session cookie is host-only.
    expect(signedIn.headers.get('access-control-allow-origin')).toBe(acmeOrigin);
    const cookie = signedIn.headers
      .getSetCookie()
      .find((value) => value.includes('better-iam.session'));
    expect(cookie).toBeDefined();
    expect(cookie).not.toMatch(/domain=/i);
    const session = await f.iam.api.auth.getSession({ token: String(signedIn.body.data!.token) });
    expect(session.identity.tenantId).toBe(f.tenantId);

    const elsewhere = await post(
      f.iam,
      `${acmeOrigin}/api/iam/auth/signIn`,
      {
        tenantId: globex.tenantId,
        email: 'owner@globex.test',
        password: 'a strong tenant owner password',
      },
      { origin: acmeOrigin },
    );
    expect(elsewhere).toMatchObject({ status: 403, body: { error: { code: 'HOST_MISMATCH' } } });

    // A page on one organization's address calling the API on another's.
    const crossed = await post(
      f.iam,
      `${acmeOrigin}/api/iam/auth/signIn`,
      { email: 'alice@acme.test', password: 'a strong alice password' },
      { origin: 'http://globex.localhost:3000' },
    );
    expect(crossed).toMatchObject({ status: 403, body: { error: { code: 'HOST_MISMATCH' } } });

    const unknownOrigin = await post(
      f.iam,
      'http://localhost:3000/api/iam/auth/signIn',
      { tenantId: f.tenantId, email: 'alice@acme.test', password: 'a strong alice password' },
      { origin: 'http://nobody.localhost:3000' },
    );
    expect(unknownOrigin).toMatchObject({
      status: 403,
      body: { error: { code: 'UNTRUSTED_ORIGIN' } },
    });
    const unknownHost = await post(f.iam, 'http://nobody.localhost:3000/api/iam/auth/signIn', {
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    expect(unknownHost).toMatchObject({ status: 404, body: { error: { code: 'NOT_FOUND' } } });
  });

  it('refuses credentials of another organization on an organization address', async () => {
    const f = await hostFixture();
    const globex = await organization(f, 'Globex', 'globex');
    const acme = 'http://acme.localhost:3000/api/iam';
    const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

    const own = await post(f.iam, `${acme}/auth/getSession`, {}, bearer(f.ownerCredential.token));
    expect(own.status).toBe(200);
    const foreign = await post(
      f.iam,
      `${acme}/auth/getSession`,
      {},
      bearer(globex.credential.token),
    );
    expect(foreign).toMatchObject({ status: 403, body: { error: { code: 'HOST_MISMATCH' } } });
    const listed = await post(
      f.iam,
      `${acme}/identities/list`,
      { tenantId: globex.tenantId },
      bearer(globex.credential.token),
    );
    expect(listed).toMatchObject({ status: 403, body: { error: { code: 'HOST_MISMATCH' } } });
    // The deployment's own address serves every organization, as before.
    const central = await post(
      f.iam,
      'http://localhost:3000/api/iam/auth/getSession',
      {},
      bearer(globex.credential.token),
    );
    expect(central.status).toBe(200);
  });

  it('looks organizations up by address and builds their sign-in URLs', async () => {
    const f = await hostFixture();
    const expected = {
      tenantId: f.tenantId,
      name: 'Acme',
      slug: 'acme',
      signInUrl: 'http://acme.localhost:3000/login',
    };
    await expect(f.iam.api.tenants.lookup({ host: 'ACME.localhost:3000' })).resolves.toMatchObject(
      expected,
    );
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).resolves.toMatchObject(expected);
    await expect(f.iam.hosts.signInUrl(f.tenantId)).resolves.toBe(expected.signInUrl);
    await expect(f.iam.hosts.resolve('acme.localhost:3000')).resolves.toMatchObject({
      tenantId: f.tenantId,
      via: 'pattern',
    });
    await expect(f.iam.hosts.resolve('localhost:3000')).resolves.toBeUndefined();
    await expect(f.iam.hosts.resolve('unrelated.example')).resolves.toBeUndefined();
    await expect(f.iam.api.tenants.lookup({ host: 'nobody.localhost:3000' })).rejects.toMatchObject(
      {
        code: 'NOT_FOUND',
      },
    );
    // On-demand TLS "ask" checks: organization addresses and the deployment's own hosts only.
    await expect(f.iam.hosts.allowed('acme.localhost:3000')).resolves.toBe(true);
    await expect(f.iam.hosts.allowed('localhost')).resolves.toBe(true);
    await expect(f.iam.hosts.allowed('nobody.localhost:3000')).resolves.toBe(false);
    await expect(f.iam.hosts.allowed('evil.example')).resolves.toBe(false);

    // A suspended organization's address stops resolving at once.
    await f.iam.api.tenants.setStatus(f.rootCredential, {
      tenantId: f.tenantId,
      status: 'suspended',
    });
    await expect(f.iam.api.tenants.lookup({ host: 'acme.localhost:3000' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(f.iam.hosts.allowed('acme.localhost:3000')).resolves.toBe(false);
  });

  it('names the organization sign-in URL on every message, for links that open there', async () => {
    const f = await hostFixture();
    await f.iam.api.identities.invite(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      name: 'Bob',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find((message) => message.template === 'member-invitation')!;
    expect(invitation.signInUrl).toBe('http://acme.localhost:3000/login');
    const rendered = renderDeliveryMessage(invitation, {
      links: { invitation: (input) => `${input.signInUrl}/join?token=${input.token}` },
    })!;
    expect(rendered.text).toContain('http://acme.localhost:3000/login/join?token=');

    // Sign-in emails carry their tenant on the message only; link builders still receive it.
    const magic = renderDeliveryMessage(
      { template: 'magic-link', to: 'a@acme.test', tenantId: 'ten_1', payload: { token: 'tok' } },
      { links: { magicLink: (input) => `/magic?tenant=${input.tenantId}&token=${input.token}` } },
    )!;
    expect(magic.text).toContain('/magic?tenant=ten_1&token=tok');
  });

  it('pins Next.js server-side calls made on an organization address', async () => {
    const f = await hostFixture();
    const globex = await organization(f, 'Globex', 'globex');
    const writes: string[] = [];
    const jar = {
      set(name: string) {
        writes.push(name);
      },
      toString: () => '',
    };
    const onAcme = createIamNext(f.iam, {
      headers: () => new Headers({ host: 'acme.localhost:3000' }),
      cookies: () => jar,
      redirect: (url: string): never => {
        throw new Error(`REDIRECT:${url}`);
      },
    });
    const signedIn = await onAcme.client().auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    expect('token' in signedIn).toBe(true);
    expect(writes).toContain('better-iam.session');
    await expect(
      onAcme.client().auth.signIn({
        tenantId: globex.tenantId,
        email: 'owner@globex.test',
        password: 'a strong tenant owner password',
      }),
    ).rejects.toMatchObject({ code: 'HOST_MISMATCH' });
  });

  it('keeps the request host through the Node transport', async () => {
    const f = await hostFixture();
    const server = createServer((req, res) => void f.iam.nodeHandler(req, res));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    const body = JSON.stringify({ email: 'alice@acme.test', password: 'a strong alice password' });
    try {
      const result = await new Promise<{ status: number; text: string }>((resolve, reject) => {
        const call = httpRequest(
          {
            host: '127.0.0.1',
            port,
            method: 'POST',
            path: '/api/iam/auth/signIn',
            headers: {
              host: 'acme.localhost:3000',
              'content-type': 'application/json',
              'x-better-iam': '1',
              'content-length': Buffer.byteLength(body),
            },
          },
          (response) => {
            let text = '';
            response.on('data', (chunk) => (text += chunk));
            response.on('end', () => resolve({ status: response.statusCode ?? 0, text }));
          },
        );
        call.on('error', reject);
        call.end(body);
      });
      expect(result.status).toBe(200);
      expect(JSON.parse(result.text)).toMatchObject({ data: { token: expect.any(String) } });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
