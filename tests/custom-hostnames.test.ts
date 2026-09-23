import { afterEach, describe, expect, it } from 'vitest';
import type { BetterIam } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

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
    body: (await response.json()) as { data?: Record<string, unknown>; error?: { code: string } },
  };
}

async function hostnameFixture(overrides: { customHostnames?: boolean; passkeys?: boolean } = {}) {
  const dns = new Map<string, string[][]>();
  const f = await organizationFixture({
    hosts: {
      patterns: ['{tenant}.localhost:3000'],
      customHostnames: overrides.customHostnames ?? true,
      cnameTarget: 'custom.signin.example.com',
    },
    domains: {
      resolveTxt: async (hostname) => {
        const records = dns.get(hostname);
        if (!records) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
        return records;
      },
    },
    ...(overrides.passkeys ? { authentication: { passkeys: { rpID: 'localhost' } } } : {}),
  });
  await f.iam.api.tenants.setSlug(f.rootCredential, { tenantId: f.tenantId, slug: 'acme' });
  await f.member('alice');
  const owner = await f.ownerSignIn();
  /** Claims and verifies a hostname for Acme. */
  const verified = async (hostname: string) => {
    const claimed = await f.iam.api.hostnames.add(owner, { tenantId: f.tenantId, hostname });
    const record = claimed.dnsRecords.verification;
    dns.set(record.name, [[record.value]]);
    const result = await f.iam.api.hostnames.verify(owner, {
      tenantId: f.tenantId,
      hostnameId: claimed.id,
    });
    return result.hostname;
  };
  return { ...f, dns, owner, verified };
}

/** Another organization with an owner session. */
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

describe('custom sign-in hostnames', () => {
  it('is off unless the deployment enables it', async () => {
    const f = await hostnameFixture({ customHostnames: false });
    await expect(
      f.iam.api.hostnames.add(f.owner, { tenantId: f.tenantId, hostname: 'login.acme.test' }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
  });

  it('claims a hostname and returns the DNS records that verify and route it', async () => {
    const f = await hostnameFixture();
    const claimed = await f.iam.api.hostnames.add(f.owner, {
      tenantId: f.tenantId,
      hostname: 'Login.Acme.Test.',
    });
    expect(claimed).toMatchObject({
      hostname: 'login.acme.test',
      status: 'pending',
      primary: false,
      url: 'http://login.acme.test/',
      dnsRecords: {
        verification: { type: 'TXT', name: '_better-iam-challenge.login.acme.test' },
        routing: { type: 'CNAME', name: 'login.acme.test', value: 'custom.signin.example.com' },
      },
    });
    expect(claimed.dnsRecords.verification.value).toMatch(/^better-iam-hostname=[\w-]{24}$/);
    for (const [hostname, code] of [
      ['login.acme.test', 'CONFLICT'],
      ['localhost', 'INVALID_INPUT'],
      // The deployment's own subdomain space cannot be claimed.
      ['globex.localhost', 'HOSTNAME_NOT_ALLOWED'],
      ['deep.acme.localhost', 'HOSTNAME_NOT_ALLOWED'],
    ])
      await expect(
        f.iam.api.hostnames.add(f.owner, { tenantId: f.tenantId, hostname }),
      ).rejects.toMatchObject({ code });
    // Pending hostnames resolve to nothing.
    await expect(f.iam.hosts.resolve('login.acme.test')).resolves.toBeUndefined();
    const listed = await f.iam.api.hostnames.list(f.owner, { tenantId: f.tenantId });
    expect(listed.map((item) => item.hostname)).toEqual(['login.acme.test']);
  });

  it('verifies through DNS, then pins requests on the hostname to the organization', async () => {
    const f = await hostnameFixture();
    const claimed = await f.iam.api.hostnames.add(f.owner, {
      tenantId: f.tenantId,
      hostname: 'login.acme.test',
    });
    await expect(
      f.iam.api.hostnames.verify(f.owner, { tenantId: f.tenantId, hostnameId: claimed.id }),
    ).resolves.toMatchObject({ verified: false, hostname: { status: 'pending' } });
    const { name, value } = claimed.dnsRecords.verification;
    f.dns.set(name, [[value]]);
    const verified = await f.iam.api.hostnames.verify(f.owner, {
      tenantId: f.tenantId,
      hostnameId: claimed.id,
    });
    expect(verified).toMatchObject({ verified: true, hostname: { status: 'verified' } });
    await expect(f.iam.hosts.resolve('login.acme.test')).resolves.toMatchObject({
      tenantId: f.tenantId,
      via: 'custom',
    });
    await expect(f.iam.hosts.allowed('login.acme.test')).resolves.toBe(true);

    const origin = 'http://login.acme.test';
    const signedIn = await post(
      f.iam,
      `${origin}/api/iam/auth/signIn`,
      { email: 'alice@acme.test', password: 'a strong alice password' },
      { origin },
    );
    expect(signedIn.status).toBe(200);
    expect(signedIn.headers.get('access-control-allow-origin')).toBe(origin);

    // Another organization cannot take a verified hostname, even with its own TXT record.
    const globex = await organization(f, 'Globex', 'globex');
    const rival = await f.iam.api.hostnames
      .add(globex.credential, {
        tenantId: globex.tenantId,
        hostname: 'login.acme.test',
      })
      .catch((error) => error);
    expect(rival).toMatchObject({ code: 'HOSTNAME_TAKEN' });
    const foreign = await post(
      f.iam,
      `${origin}/api/iam/auth/getSession`,
      {},
      {
        authorization: `Bearer ${globex.credential.token}`,
      },
    );
    expect(foreign).toMatchObject({ status: 403, body: { error: { code: 'HOST_MISMATCH' } } });
  });

  it('makes a verified hostname the primary sign-in address, and releases it', async () => {
    const f = await hostnameFixture();
    const pending = await f.iam.api.hostnames.add(f.owner, {
      tenantId: f.tenantId,
      hostname: 'sso.acme.test',
    });
    await expect(
      f.iam.api.hostnames.setPrimary(f.owner, { tenantId: f.tenantId, hostnameId: pending.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const hostname = await f.verified('login.acme.test');
    const primary = await f.iam.api.hostnames.setPrimary(f.owner, {
      tenantId: f.tenantId,
      hostnameId: hostname.id,
    });
    expect(primary).toMatchObject({
      primary: { hostname: 'login.acme.test', primary: true },
      signInUrl: 'http://login.acme.test/',
    });
    await expect(f.iam.hosts.signInUrl(f.tenantId)).resolves.toBe('http://login.acme.test/');
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).resolves.toMatchObject({
      signInUrl: 'http://login.acme.test/',
    });
    const back = await f.iam.api.hostnames.setPrimary(f.owner, {
      tenantId: f.tenantId,
      hostnameId: null,
    });
    expect(back).toMatchObject({ primary: null, signInUrl: 'http://acme.localhost:3000/' });

    await f.iam.api.hostnames.delete(f.owner, { tenantId: f.tenantId, hostnameId: hostname.id });
    await expect(f.iam.hosts.resolve('login.acme.test')).resolves.toBeUndefined();
    await expect(f.iam.hosts.allowed('login.acme.test')).resolves.toBe(false);
  });

  it('refuses passkey ceremonies on a hostname outside the passkey domain', async () => {
    const f = await hostnameFixture({ passkeys: true });
    await f.verified('login.acme.test');
    const origin = 'http://login.acme.test';
    const custom = await post(
      f.iam,
      `${origin}/api/iam/auth/beginPasskeyAuthentication`,
      {},
      { origin },
    );
    expect(custom).toMatchObject({
      status: 400,
      body: { error: { code: 'FEATURE_DISABLED' } },
    });
    // The organization's subdomain is under the RP ID, so passkeys work there.
    const subdomain = 'http://acme.localhost:3000';
    const begun = await post(
      f.iam,
      `${subdomain}/api/iam/auth/beginPasskeyAuthentication`,
      {},
      { origin: subdomain },
    );
    expect(begun.status).toBe(200);
    expect(begun.body.data).toMatchObject({ options: { rpId: 'localhost' } });
  });
});
