import { createRequire } from 'node:module';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { betterIam, type BetterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamClient, IamClientError, type ClientCallOptions } from '@better-iam/client';
import { IamError, type AttributeType, type IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const origin = 'https://app.example.test';
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

/**
 * The application under test: a product with application-owned documents (resolved by callback),
 * IAM-managed projects (declared in configuration), and tenant-defined resource types.
 */
async function application() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const documents = new Map<
    string,
    { id: string; tenantId: string; ownerId: string; classification: string }
  >();
  const iam = betterIam({
    database,
    secret: 'application-test-secret-with-at-least-32-characters',
    baseURL: origin,
    trustedOrigins: [origin],
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    onboarding: { mode: 'linked' },
    permissions: {
      mode: 'tenant-defined',
      resourceTypes: {
        document: {
          description: 'Application-owned document',
          actions: ['documents:read', 'documents:write'],
          attributes: { classification: 'string', ownerId: 'string' },
        },
        project: {
          description: 'IAM-managed project',
          managed: true,
          actions: ['projects:read', 'projects:manage'],
          attributes: { archived: 'boolean' },
        },
      },
    },
    async resolveResource(reference) {
      const document = reference.type === 'document' ? documents.get(reference.id) : undefined;
      if (!document) throw new IamError('NOT_FOUND', 'Document not found', 404);
      return {
        type: 'document',
        id: document.id,
        tenantId: document.tenantId,
        attributes: { classification: document.classification, ownerId: document.ownerId },
      };
    },
  });
  await iam.initialize();
  const deliveries = async (template: string, to: string) => {
    await iam.auth.dispatchOutbox();
    return inbox.find((message) => message.template === template && message.to === to)!;
  };
  return { iam, database, inbox, documents, deliveries };
}

/** A browser: the typed client plus a cookie jar, talking to the server through iam.handler like a real deployment would. */
function browser(iam: BetterIam) {
  let cookie: string | undefined;
  const fetcher: typeof fetch = async (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set('origin', origin);
    if (cookie) headers.set('cookie', cookie);
    const response = await iam.handler(new Request(input, { ...init, headers }));
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(';');
      const [name, value] = pair!.split('=');
      if (name !== '__Host-better-iam.session') continue;
      cookie =
        !value || attributes.some((attribute) => attribute.trim() === 'Max-Age=0')
          ? undefined
          : `${name}=${value}`;
    }
    return response;
  };
  return {
    client: createIamClient<typeof iam>({ baseURL: origin, fetch: fetcher }),
    credential: () => ({ headers: { origin, ...(cookie ? { cookie } : {}) } }),
  };
}

describe('application-level integration through HTTP and the typed client', () => {
  it('runs a multi-person organization: aliases, invitations, custom roles, resource types, advisory and enforced checks', async () => {
    const app = await application();
    const { iam } = app;
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
      slug: 'platform',
    });

    // The platform administrator signs in through the browser client and completes MFA enrollment.
    const rootBrowser = browser(iam);
    const challenge = await rootBrowser.client.auth.signIn({
      tenantId: root.tenant.id,
      email: 'root@example.test',
      password: 'a strong root test password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
    const enrollment = await rootBrowser.client.auth.beginMfa({
      tenantId: root.tenant.id,
      challenge: challenge.challenge,
    });
    await rootBrowser.client.auth.confirmMfa({
      credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
      code: authenticator.generate(enrollment.secret),
    });
    expect((await rootBrowser.client.auth.getSession()).identity.rootAdmin).toBe(true);

    // Root creates an organization with a sign-in alias; the owner enrolls from the delivered invitation.
    const created = await rootBrowser.client.tenants.create({
      parentId: root.tenant.id,
      type: 'organization',
      name: 'Acme',
      slug: 'acme',
      ownerEmail: 'owner@acme.test',
    });
    expect(created).not.toHaveProperty('invitationToken');
    expect(created.tenant.slug).toBe('acme');
    const ownerBrowser = browser(iam);
    await expect(ownerBrowser.client.tenants.lookup({ slug: 'acme' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
      status: 404,
    });
    const ownerInvitation = await app.deliveries('owner-invitation', 'owner@acme.test');
    const owner = await ownerBrowser.client.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: ownerInvitation.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected MFA');
    const acme = (await ownerBrowser.client.tenants.lookup({ slug: 'acme' })).tenantId;
    expect(acme).toBe(created.tenant.id);

    // The owner shapes the organization: a tenant-defined resource type and custom roles built from permissions.
    const invoice = await ownerBrowser.client.resourceTypes.register({
      tenantId: acme,
      name: 'invoice',
      description: 'Customer invoice',
      actions: ['read', 'approve'],
      attributes: { amount: 'number' },
    });
    expect(invoice).toMatchObject({
      source: 'tenant',
      managed: true,
      actions: ['invoice:read', 'invoice:approve'],
    });
    expect(
      (await ownerBrowser.client.resourceTypes.list({ tenantId: acme }))
        .map((type) => type.name)
        .sort(),
    ).toEqual(['document', 'invoice', 'project']);
    expect(
      (await ownerBrowser.client.actions.list({ tenantId: acme }))
        .filter((action) => action.resourceType === 'invoice')
        .map((action) => action.name)
        .sort(),
    ).toEqual(['invoice:approve', 'invoice:read']);
    const approver = await ownerBrowser.client.roles.create({
      tenantId: acme,
      name: 'Approver',
      description: 'Approves invoices under 10,000',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['invoice:read', 'projects:read', 'documents:read'],
            resources: ['*'],
          },
          {
            effect: 'allow',
            actions: ['invoice:approve'],
            resources: ['invoice/*'],
            conditions: { NumericLessThan: { 'resource.amount': 10000 } },
          },
        ],
      },
    });
    const viewer = await ownerBrowser.client.roles.create({
      tenantId: acme,
      name: 'Viewer',
      permissions: ['invoice:read', 'documents:read'],
    });
    await expect(
      ownerBrowser.client.roles.create({
        tenantId: acme,
        name: 'Broken',
        permissions: ['invoice:delete'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION', status: 400 });

    // Two people are invited into the same organization with different roles and enroll from their own browsers.
    await ownerBrowser.client.identities.invite({
      tenantId: acme,
      email: 'alice@acme.test',
      name: 'Alice',
      roleIds: [approver.id],
    });
    await ownerBrowser.client.identities.invite({
      tenantId: acme,
      email: 'bob@acme.test',
      roleIds: [viewer.id],
    });
    const aliceBrowser = browser(iam);
    const bobBrowser = browser(iam);
    const alice = await aliceBrowser.client.identities.acceptInvitation({
      tenantId: acme,
      token: (await app.deliveries('member-invitation', 'alice@acme.test')).payload.token!,
      password: 'a strong alice test password',
    });
    if (!('token' in alice)) throw new Error('Unexpected MFA');
    await expect(
      bobBrowser.client.identities.acceptInvitation({
        tenantId: acme,
        token: (await app.deliveries('member-invitation', 'bob@acme.test')).payload.token!,
        password: 'a strong bob test password',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const bob = await bobBrowser.client.identities.acceptInvitation({
      tenantId: acme,
      token: (await app.deliveries('member-invitation', 'bob@acme.test')).payload.token!,
      name: 'Bob',
      password: 'a strong bob test password',
    });
    if (!('token' in bob)) throw new Error('Unexpected MFA');
    expect(
      (await ownerBrowser.client.identities.list({ tenantId: acme }))
        .map((identity) => identity.email)
        .sort(),
    ).toEqual(['alice@acme.test', 'bob@acme.test', 'owner@acme.test']);
    expect(
      (
        await ownerBrowser.client.identities.listBindings({
          tenantId: acme,
          identityId: alice.identity.id,
        })
      ).map((binding) => binding.role?.name),
    ).toEqual(['Approver']);

    // Bob signs out and returns through the alias-based login the application would show.
    await bobBrowser.client.auth.signOut();
    await expect(bobBrowser.client.auth.getSession()).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      status: 401,
    });
    const bobTenant = await bobBrowser.client.tenants.lookup({ slug: 'acme' });
    const bobLogin = await bobBrowser.client.auth.signIn({
      tenantId: bobTenant.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob test password',
    });
    if (!('token' in bobLogin)) throw new Error('Unexpected MFA');
    expect((await bobBrowser.client.auth.getSession()).identity.id).toBe(bob.identity.id);

    // Resources: managed projects and invoices are registered with IAM; documents stay application-owned.
    await ownerBrowser.client.resources.register({
      tenantId: acme,
      type: 'project',
      id: 'website',
      attributes: { archived: false },
    });
    await ownerBrowser.client.resources.register({
      tenantId: acme,
      type: 'invoice',
      id: 'inv-1',
      attributes: { amount: 250 },
      ownerId: bob.identity.id,
    });
    await ownerBrowser.client.resources.register({
      tenantId: acme,
      type: 'invoice',
      id: 'inv-2',
      attributes: { amount: 25000 },
    });
    await expect(
      ownerBrowser.client.resources.register({
        tenantId: acme,
        type: 'invoice',
        id: 'inv-3',
        attributes: { amount: 'lots' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      ownerBrowser.client.resources.register({ tenantId: acme, type: 'document', id: 'app-owned' }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    app.documents.set('handbook', {
      id: 'handbook',
      tenantId: acme,
      ownerId: owner.identity.id,
      classification: 'internal',
    });
    expect(
      (await ownerBrowser.client.resources.list({ tenantId: acme, type: 'invoice' })).map(
        (resource) => resource.resourceId,
      ),
    ).toEqual(['inv-1', 'inv-2']);

    // Advisory checks drive the UI; the batch mirrors the single decision and never leaks matched statements.
    const checks = [
      { action: 'invoice:read', resource: { type: 'invoice', id: 'inv-1' } },
      { action: 'invoice:approve', resource: { type: 'invoice', id: 'inv-1' } },
      { action: 'invoice:approve', resource: { type: 'invoice', id: 'inv-2' } },
      { action: 'projects:read', resource: { type: 'project', id: 'website' } },
      { action: 'projects:manage', resource: { type: 'project', id: 'website' } },
      { action: 'documents:read', resource: { type: 'document', id: 'handbook' } },
      { action: 'iam:identities:create', resource: { type: 'iam', id: acme } },
    ];
    const aliceView = await aliceBrowser.client.authorizeMany({ tenantId: acme, checks });
    expect(aliceView.results.map((result) => result.allowed)).toEqual([
      true,
      true,
      false,
      true,
      false,
      true,
      false,
    ]);
    expect(aliceView.results[0]).not.toHaveProperty('matched');
    const bobView = await bobBrowser.client.authorizeMany({ tenantId: acme, checks });
    expect(bobView.results.map((result) => result.allowed)).toEqual([
      true,
      false,
      false,
      false,
      false,
      true,
      false,
    ]);
    const ownerView = await ownerBrowser.client.authorizeMany({ tenantId: acme, checks });
    expect(ownerView.results.every((result) => result.allowed)).toBe(true);
    expect(
      (
        await bobBrowser.client.authorize({
          tenantId: acme,
          action: 'invoice:approve',
          resource: { type: 'invoice', id: 'inv-1' },
        })
      ).allowed,
    ).toBe(false);

    // Server-side enforcement uses the same cookie credential the browser holds.
    await expect(
      iam.require({
        ...aliceBrowser.credential(),
        tenantId: acme,
        action: 'invoice:approve',
        resource: { type: 'invoice', id: 'inv-1' },
      }),
    ).resolves.toBeUndefined();
    await expect(
      iam.require({
        ...bobBrowser.credential(),
        tenantId: acme,
        action: 'invoice:approve',
        resource: { type: 'invoice', id: 'inv-1' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iam.require({
        ...aliceBrowser.credential(),
        tenantId: acme,
        action: 'invoice:approve',
        resource: { type: 'invoice', id: 'missing' },
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Tenant isolation holds through the client: another organization is invisible even to an authenticated member.
    const beta = await rootBrowser.client.tenants.create({
      parentId: root.tenant.id,
      type: 'organization',
      name: 'Beta',
      slug: 'beta',
      ownerEmail: 'alice@acme.test',
    });
    const aliceBetaBrowser = browser(iam);
    const aliceBeta = await aliceBetaBrowser.client.tenants.acceptInvitation({
      tenantId: beta.tenant.id,
      token: (await app.deliveries('owner-invitation', 'alice@acme.test')).payload.token!,
      name: 'Alice',
      password: 'a strong beta owner password',
    });
    if (!('token' in aliceBeta)) throw new Error('Unexpected MFA');
    // A resource owned by Acme cannot be evaluated under Beta's tenant, and Beta's resources are invisible to an Acme
    // session: a principal of another tenant is refused before any resource is resolved, so it learns nothing.
    expect(
      await aliceBrowser.client.authorize({
        tenantId: beta.tenant.id,
        action: 'documents:read',
        resource: { type: 'document', id: 'handbook' },
      }),
    ).toMatchObject({ allowed: false });
    await aliceBetaBrowser.client.resources.register({
      tenantId: beta.tenant.id,
      type: 'project',
      id: 'beta-site',
      attributes: { archived: false },
    });
    expect(
      (
        await aliceBrowser.client.authorize({
          tenantId: beta.tenant.id,
          action: 'projects:read',
          resource: { type: 'project', id: 'beta-site' },
        })
      ).allowed,
    ).toBe(false);
    expect(
      (
        await aliceBetaBrowser.client.authorize({
          tenantId: beta.tenant.id,
          action: 'projects:read',
          resource: { type: 'project', id: 'beta-site' },
        })
      ).allowed,
    ).toBe(true);
    await expect(bobBrowser.client.tenants.get({ tenantId: beta.tenant.id })).rejects.toMatchObject(
      { code: 'ACCESS_DENIED', status: 403 },
    );
    await expect(
      bobBrowser.client.resources.list({ tenantId: beta.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // The same person holds separate identities in Acme and Beta; linking them enables an account switcher without merging permissions.
    expect(await aliceBrowser.client.links.list()).toEqual([]);
    const link = await aliceBrowser.client.links.create({
      targetCredential: { token: aliceBeta.token },
    });
    expect(await aliceBrowser.client.links.list()).toMatchObject([
      {
        id: link.id,
        tenantId: beta.tenant.id,
        tenantName: 'Beta',
        tenantSlug: 'beta',
        email: 'alice@acme.test',
      },
    ]);
    await aliceBrowser.client.links.switch({
      linkId: link.id,
      targetCredential: { token: aliceBeta.token },
    });
    expect((await aliceBrowser.client.auth.getSession()).session.tenantId).toBe(beta.tenant.id);
    expect(
      (
        await aliceBrowser.client.authorize({
          tenantId: acme,
          action: 'invoice:read',
          resource: { type: 'invoice', id: 'inv-1' },
        })
      ).allowed,
    ).toBe(false);

    // Deprovisioning takes effect on the next request.
    await ownerBrowser.client.identities.setStatus({
      tenantId: acme,
      identityId: bob.identity.id,
      status: 'disabled',
    });
    await expect(bobBrowser.client.auth.getSession()).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(
      bobBrowser.client.authorize({
        tenantId: acme,
        action: 'invoice:read',
        resource: { type: 'invoice', id: 'inv-1' },
      }),
    ).rejects.toBeInstanceOf(IamClientError);
    expect(
      (await ownerBrowser.client.audit.list({ tenantId: acme })).some(
        (event) => event.action === 'identity:invitation:accept',
      ),
    ).toBe(true);
  });

  it('rejects requests that bypass the browser boundary and keeps public routes limited to discovery and invitation redemption', async () => {
    const { iam } = await application();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const call = (path: string, body: unknown, headers: Record<string, string> = {}) =>
      iam.handler(
        new Request(`${origin}/api/iam/${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-better-iam': '1', origin, ...headers },
          body: JSON.stringify(body),
        }),
      );
    expect((await call('tenants/lookup', { slug: 'missing' })).status).toBe(404);
    expect((await call('tenants/lookup', { slug: 'Not a slug!' })).status).toBe(400);
    expect(
      (
        await call('identities/acceptInvitation', {
          tenantId: root.tenant.id,
          token: 'guess',
          password: 'a strong guessed password',
        })
      ).status,
    ).toBe(400);
    expect(
      (await call('identities/invite', { tenantId: root.tenant.id, email: 'x@example.test' }))
        .status,
    ).toBe(401);
    expect(
      (await call('resources/register', { tenantId: root.tenant.id, type: 'project', id: 'x' }))
        .status,
    ).toBe(401);
    expect(
      (
        await call('authorizeMany', {
          tenantId: root.tenant.id,
          checks: [{ action: 'projects:read', resource: { type: 'project', id: 'x' } }],
        })
      ).status,
    ).toBe(401);
    expect((await call('authorizeMany', { tenantId: root.tenant.id, checks: [] })).status).toBe(
      400,
    );
    expect(
      (await call('tenants/lookup', { slug: 'missing' }, { origin: 'https://attacker.example' }))
        .status,
    ).toBe(403);
    expect(
      (await call('tenants/lookup', { slug: 'missing' }, { 'x-better-iam': '0' })).status,
    ).toBe(403);
  });

  it('infers request and response types for the new surface from the server instance', async () => {
    const { iam } = await application();
    const client = createIamClient<typeof iam>({
      baseURL: origin,
      fetch: async () => Response.json({ data: {} }),
    });
    expectTypeOf(client.identities.invite).parameter(0).toEqualTypeOf<{
      tenantId: string;
      email: string;
      name?: string;
      roleIds?: string[];
      groupIds?: string[];
    }>();
    expectTypeOf(client.identities.acceptInvitation)
      .parameter(0)
      .toEqualTypeOf<{ tenantId: string; token: string; name?: string; password: string }>();
    expectTypeOf(client.tenants.lookup)
      .parameter(0)
      .toEqualTypeOf<{ slug?: string; host?: string }>();
    expectTypeOf(client.tenants.lookup).returns.resolves.toEqualTypeOf<{
      tenantId: string;
      name: string;
      type: string;
      slug: string;
      region?: string;
      signInUrl?: string;
    }>();
    expectTypeOf(client.links.list).parameter(0).toEqualTypeOf<ClientCallOptions | undefined>();
    expectTypeOf(client.roles.create)
      .parameter(0)
      .toHaveProperty('permissions')
      .toEqualTypeOf<string[] | undefined>();
    expectTypeOf(client.resourceTypes.register)
      .parameter(0)
      .toHaveProperty('attributes')
      .toEqualTypeOf<Record<string, AttributeType> | undefined>();
    expectTypeOf(client.resources.register)
      .parameter(0)
      .toHaveProperty('parentId')
      .toEqualTypeOf<string | undefined>();
    expectTypeOf(client.authorizeMany).parameter(0).toEqualTypeOf<{
      tenantId: string;
      checks: { action: string; resource: { type: string; id: string } }[];
    }>();
    expectTypeOf(client.authorizeMany)
      .returns.resolves.toHaveProperty('results')
      .items.toHaveProperty('allowed')
      .toEqualTypeOf<boolean>();
    // @ts-expect-error credentials are never part of the browser contract
    expectTypeOf(client.identities.invite).parameter(0).toHaveProperty('headers');
  });
});
