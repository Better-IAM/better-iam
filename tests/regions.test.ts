import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, WrongRegionError, type BetterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamClient, IamClientError } from '@better-iam/client';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const regions = {
  current: 'us-east-1',
  regions: {
    'us-east-1': { label: 'US East' },
    'eu-west-1': { label: 'Europe', baseURL: 'https://eu.example.com' },
  },
};
const hosts = { patterns: ['{tenant}.signin.{region}.localhost:3000'], signInPath: '/login' };

async function post(iam: BetterIam, url: string, body: Record<string, unknown>) {
  const response = await iam.handler(
    new Request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
      body: JSON.stringify(body),
    }),
  );
  return {
    status: response.status,
    body: (await response.json()) as {
      data?: Record<string, unknown>;
      error?: { code: string; region?: string; location?: string };
    },
  };
}

/** An organization with an alias, optionally homed in another region. */
async function organization(f: OrganizationFixture, name: string, slug: string, region?: string) {
  const created = await f.iam.api.tenants.create(f.rootCredential, {
    parentId: f.root.tenant.id,
    name,
    type: 'organization',
    ownerEmail: `owner@${slug}.test`,
    slug,
    ...(region ? { region } : {}),
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
  return { tenant: created.tenant, credential: { token: owner.token } };
}

describe('multi-region deployments', () => {
  it('validates the region settings', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    const base = {
      database,
      secret: 'regions-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    };
    const cases: [object, RegExp][] = [
      [{ current: 'us-east-1', regions: { 'eu-west-1': {} } }, /current must be one of regions/],
      [{ current: 'US East', regions: { 'us-east-1': {} } }, /current must be a region name/],
      [{ current: 'us-east-1', regions: {} }, /1 to 64 regions/],
      [
        { current: 'us-east-1', regions: { 'us-east-1': { baseURL: 'http://eu.example.com' } } },
        /must use HTTPS outside localhost/,
      ],
      [
        { current: 'us-east-1', regions: { 'us-east-1': {} }, locate: 'nope' },
        /locate must be a function/,
      ],
    ];
    for (const [option, message] of cases)
      expect(() => betterIam({ ...base, regions: option as never })).toThrow(message);
    await database.close();
  });

  it('homes organizations in a region, inherited by their children', async () => {
    const f = await organizationFixture({ regions, hosts });
    // The first organizations under the region-less root are homed where they are created.
    expect((await f.iam.api.tenants.get(f.rootCredential, { tenantId: f.tenantId })).region).toBe(
      'us-east-1',
    );
    const globex = await organization(f, 'Globex', 'globex', 'eu-west-1');
    expect(globex.tenant.region).toBe('eu-west-1');
    await expect(organization(f, 'Initech', 'initech', 'ap-south-1')).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    // Sign-in URLs name each organization's own region.
    await expect(f.iam.hosts.signInUrl(globex.tenant.id)).resolves.toBe(
      'http://globex.signin.eu-west-1.localhost:3000/login',
    );
    expect(f.iam.hosts.region).toBe('us-east-1');
  });

  it('sends sign-in for an organization homed elsewhere to its region', async () => {
    const f = await organizationFixture({ regions, hosts });
    await f.iam.api.tenants.setSlug(f.rootCredential, { tenantId: f.tenantId, slug: 'acme' });
    await f.member('alice');
    const globex = await organization(f, 'Globex', 'globex', 'eu-west-1');
    const globexUrl = 'http://globex.signin.eu-west-1.localhost:3000/login';

    const lookup = f.iam.api.tenants.lookup({ slug: 'globex' });
    await expect(lookup).rejects.toBeInstanceOf(WrongRegionError);
    await expect(lookup).rejects.toMatchObject({
      code: 'WRONG_REGION',
      status: 421,
      region: 'eu-west-1',
      location: globexUrl,
    });
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).resolves.toMatchObject({
      region: 'us-east-1',
      signInUrl: 'http://acme.signin.us-east-1.localhost:3000/login',
    });

    // Over HTTP the refusal carries the region and the address to go to.
    const central = await post(f.iam, 'http://localhost:3000/api/iam/auth/signIn', {
      tenantId: globex.tenant.id,
      email: 'owner@globex.test',
      password: 'a strong tenant owner password',
    });
    expect(central).toMatchObject({
      status: 421,
      body: { error: { code: 'WRONG_REGION', region: 'eu-west-1', location: globexUrl } },
    });
    const onItsAddress = await post(
      f.iam,
      'http://globex.signin.eu-west-1.localhost:3000/api/iam/auth/signIn',
      { email: 'owner@globex.test', password: 'a strong tenant owner password' },
    );
    expect(onItsAddress).toMatchObject({ status: 421, body: { error: { code: 'WRONG_REGION' } } });
    // An address naming the wrong region redirects to the organization's own.
    const wrongName = await post(
      f.iam,
      'http://acme.signin.eu-west-1.localhost:3000/api/iam/auth/signIn',
      { email: 'alice@acme.test', password: 'a strong alice password' },
    );
    expect(wrongName).toMatchObject({
      status: 421,
      body: {
        error: {
          code: 'WRONG_REGION',
          region: 'us-east-1',
          location: 'http://acme.signin.us-east-1.localhost:3000/login',
        },
      },
    });
    const home = await post(
      f.iam,
      'http://acme.signin.us-east-1.localhost:3000/api/iam/auth/signIn',
      { email: 'alice@acme.test', password: 'a strong alice password' },
    );
    expect(home.status).toBe(200);

    // The typed client surfaces the redirect.
    const client = createIamClient<BetterIam>({
      baseURL: 'http://localhost:3000',
      fetch: (input, init) => f.iam.handler(new Request(input, init)),
    });
    const refused = await client.tenants.lookup({ slug: 'globex' }).catch((error) => error);
    expect(refused).toBeInstanceOf(IamClientError);
    expect(refused).toMatchObject({
      code: 'WRONG_REGION',
      region: 'eu-west-1',
      location: globexUrl,
    });
  });

  it('moves an organization to another region (root administrators only)', async () => {
    const f = await organizationFixture({ regions, hosts });
    await f.iam.api.tenants.setSlug(f.rootCredential, { tenantId: f.tenantId, slug: 'acme' });
    await expect(
      f.iam.api.tenants.setRegion(await f.ownerSignIn(), {
        tenantId: f.tenantId,
        region: 'eu-west-1',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.tenants.setRegion(f.rootCredential, { tenantId: f.tenantId, region: 'mars-1' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const moved = await f.iam.api.tenants.setRegion(f.rootCredential, {
      tenantId: f.tenantId,
      region: 'eu-west-1',
    });
    expect(moved.region).toBe('eu-west-1');
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).rejects.toMatchObject({
      code: 'WRONG_REGION',
      location: 'http://acme.signin.eu-west-1.localhost:3000/login',
    });
    // Clearing it inherits the parent's region again: the root has none, so every region serves it.
    const cleared = await f.iam.api.tenants.setRegion(f.rootCredential, {
      tenantId: f.tenantId,
      region: null,
    });
    expect(cleared.region).toBeUndefined();
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).resolves.toMatchObject({
      tenantId: f.tenantId,
    });
  });

  it('finds aliases kept in another region database with regions.locate', async () => {
    const located: string[] = [];
    const f = await organizationFixture({
      hosts,
      regions: {
        ...regions,
        locate: async (alias) => {
          located.push(alias);
          return alias === 'initech' ? 'eu-west-1' : undefined;
        },
      },
    });
    await expect(f.iam.api.tenants.lookup({ slug: 'initech' })).rejects.toMatchObject({
      code: 'WRONG_REGION',
      region: 'eu-west-1',
      location: 'http://initech.signin.eu-west-1.localhost:3000/login',
    });
    await expect(f.iam.api.tenants.lookup({ slug: 'nobody' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    const onItsAddress = await post(
      f.iam,
      'http://initech.signin.us-east-1.localhost:3000/api/iam/auth/signIn',
      { email: 'someone@initech.test', password: 'a strong password here' },
    );
    expect(onItsAddress).toMatchObject({
      status: 421,
      body: { error: { code: 'WRONG_REGION', region: 'eu-west-1' } },
    });
    expect(located).toEqual(['initech', 'nobody', 'initech']);
    // With separate databases, organizations are created on the deployment of their own region.
    await expect(
      f.iam.api.tenants.create(f.rootCredential, {
        parentId: f.root.tenant.id,
        name: 'Hooli',
        type: 'organization',
        ownerEmail: 'owner@hooli.test',
        region: 'eu-west-1',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
