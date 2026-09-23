import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});
const origin = 'http://localhost:3000';

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const dns = new Map<string, string[][]>();
  const lookups: string[] = [];
  const iam = betterIam({
    database,
    secret: 'domains-test-secret-with-at-least-32-characters',
    baseURL: origin,
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    domains: {
      resolveTxt: async (hostname) => {
        lookups.push(hostname);
        const records = dns.get(hostname);
        if (!records) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
        return records;
      },
    },
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
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
  const organization = async (name: string, ownerEmail: string) => {
    const created = await iam.api.tenants.create(
      { token: session.token },
      { parentId: root.tenant.id, name, type: 'organization', ownerEmail },
    );
    await iam.auth.dispatchOutbox();
    const invitation = inbox.find(
      (message) =>
        message.tenantId === created.tenant.id && message.template === 'owner-invitation',
    )!;
    const owner = await iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: invitation.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected owner MFA');
    return { tenantId: created.tenant.id, credential: { token: owner.token } };
  };
  return { iam, dns, lookups, organization, rootCredential: { token: session.token } };
}

describe('verified domains and home-realm discovery', () => {
  it('claims, verifies through DNS, and discovers the owning organization', async () => {
    const f = await fixture();
    const acme = await f.organization('Acme', 'owner@acme.test');
    const claimed = await f.iam.api.domains.add(acme.credential, {
      tenantId: acme.tenantId,
      domain: 'Acme.Example.',
    });
    expect(claimed).toMatchObject({
      domain: 'acme.example',
      status: 'pending',
      dnsRecord: { type: 'TXT', name: '_better-iam-challenge.acme.example' },
    });
    expect(claimed.dnsRecord.value).toMatch(/^better-iam-verification=[\w-]{24}$/);
    for (const [domain, code] of [
      ['gmail.com', 'DOMAIN_NOT_ALLOWED'],
      ['not a domain', 'INVALID_INPUT'],
      ['localhost', 'INVALID_INPUT'],
      ['10.0.0.1', 'INVALID_INPUT'],
      ['-bad.example', 'INVALID_INPUT'],
      ['acme.example', 'CONFLICT'],
    ])
      await expect(
        f.iam.api.domains.add(acme.credential, { tenantId: acme.tenantId, domain }),
      ).rejects.toMatchObject({ code });

    // Pending domains are not discoverable, and a missing record leaves the claim pending.
    await expect(f.iam.api.domains.discover({ email: 'jane@acme.example' })).rejects.toMatchObject({
      status: 404,
    });
    const pending = await f.iam.api.domains.verify(acme.credential, {
      tenantId: acme.tenantId,
      domainId: claimed.id,
    });
    expect(pending.verified).toBe(false);
    expect(pending.domain.lastCheckedAt).toBeTypeOf('number');

    // TXT records may arrive split into chunks; the joined value must match exactly.
    const value = claimed.dnsRecord.value;
    f.dns.set(claimed.dnsRecord.name, [['unrelated'], [value.slice(0, 10), value.slice(10)]]);
    const verified = await f.iam.api.domains.verify(acme.credential, {
      tenantId: acme.tenantId,
      domainId: claimed.id,
    });
    expect(verified.verified).toBe(true);
    expect(verified.domain.status).toBe('verified');
    expect(await f.iam.api.domains.discover({ email: 'Jane@ACME.example' })).toEqual({
      domain: 'acme.example',
      tenantId: acme.tenantId,
      name: 'Acme',
      type: 'organization',
      allowedMethods: null,
      requireMfa: false,
    });
    // Re-verifying a verified domain does not query DNS again.
    const lookups = f.lookups.length;
    await f.iam.api.domains.verify(acme.credential, {
      tenantId: acme.tenantId,
      domainId: claimed.id,
    });
    expect(f.lookups.length).toBe(lookups);
    const list = await f.iam.api.domains.list(acme.credential, { tenantId: acme.tenantId });
    expect(list.map((row) => row.domain)).toEqual(['acme.example']);

    // Discovery reflects the tenant's sign-in requirements.
    await f.iam.api.tenants.setAuthPolicy(acme.credential, {
      tenantId: acme.tenantId,
      authPolicy: { requireMfa: true, allowedMethods: ['passkey'] },
    });
    expect(await f.iam.api.domains.discover({ domain: 'acme.example' })).toMatchObject({
      allowedMethods: ['passkey'],
      requireMfa: true,
    });
  });

  it('keeps one owner per domain, isolates tenants, and stops discovery on release or suspension', async () => {
    const f = await fixture();
    const acme = await f.organization('Acme', 'owner@acme.test');
    const rival = await f.organization('Rival', 'owner@rival.test');
    const acmeClaim = await f.iam.api.domains.add(acme.credential, {
      tenantId: acme.tenantId,
      domain: 'shared.example',
    });
    // Two organizations may hold pending claims; only the one that proves DNS control wins.
    const rivalClaim = await f.iam.api.domains.add(rival.credential, {
      tenantId: rival.tenantId,
      domain: 'shared.example',
    });
    expect(rivalClaim.dnsRecord.value).not.toBe(acmeClaim.dnsRecord.value);
    f.dns.set(acmeClaim.dnsRecord.name, [[acmeClaim.dnsRecord.value]]);
    await f.iam.api.domains.verify(acme.credential, {
      tenantId: acme.tenantId,
      domainId: acmeClaim.id,
    });
    // The rival's own token is not published, so it stays pending; publishing it cannot steal ownership.
    expect(
      (
        await f.iam.api.domains.verify(rival.credential, {
          tenantId: rival.tenantId,
          domainId: rivalClaim.id,
        })
      ).verified,
    ).toBe(false);
    f.dns.set(acmeClaim.dnsRecord.name, [[rivalClaim.dnsRecord.value]]);
    await expect(
      f.iam.api.domains.verify(rival.credential, {
        tenantId: rival.tenantId,
        domainId: rivalClaim.id,
      }),
    ).rejects.toMatchObject({ code: 'DOMAIN_TAKEN' });
    await expect(
      f.iam.api.domains.add(rival.credential, {
        tenantId: rival.tenantId,
        domain: 'other.example',
      }),
    ).resolves.toBeDefined();
    await expect(
      f.iam.api.domains.add(
        rival.credential,
        // Already verified elsewhere: a new claim is refused outright.
        { tenantId: rival.tenantId, domain: 'shared.example' },
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // Cross-tenant access to another organization's claim is not found.
    await expect(
      f.iam.api.domains.delete(rival.credential, {
        tenantId: rival.tenantId,
        domainId: acmeClaim.id,
      }),
    ).rejects.toMatchObject({ status: 404 });

    expect((await f.iam.api.domains.discover({ email: 'a@shared.example' })).tenantId).toBe(
      acme.tenantId,
    );
    await f.iam.api.tenants.setStatus(f.rootCredential, {
      tenantId: acme.tenantId,
      status: 'suspended',
    });
    await expect(f.iam.api.domains.discover({ email: 'a@shared.example' })).rejects.toMatchObject({
      status: 404,
    });
    await f.iam.api.tenants.setStatus(f.rootCredential, {
      tenantId: acme.tenantId,
      status: 'active',
    });
    // Suspension ended the organization's sessions; the owner signs in again.
    const again = await f.iam.api.auth.signIn({
      tenantId: acme.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    if (!('token' in again)) throw new Error('Unexpected MFA');
    await f.iam.api.domains.delete(
      { token: again.token },
      {
        tenantId: acme.tenantId,
        domainId: acmeClaim.id,
      },
    );
    await expect(f.iam.api.domains.discover({ email: 'a@shared.example' })).rejects.toMatchObject({
      status: 404,
    });
    // Released: the rival can now verify its pending claim.
    expect(
      (
        await f.iam.api.domains.verify(rival.credential, {
          tenantId: rival.tenantId,
          domainId: rivalClaim.id,
        })
      ).verified,
    ).toBe(true);
  });

  it('serves discovery publicly over HTTP while management requires permission', async () => {
    const f = await fixture();
    const acme = await f.organization('Acme', 'owner@acme.test');
    const claim = await f.iam.api.domains.add(acme.credential, {
      tenantId: acme.tenantId,
      domain: 'web.example',
    });
    f.dns.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
    await f.iam.api.domains.verify(acme.credential, {
      tenantId: acme.tenantId,
      domainId: claim.id,
    });
    const call = (path: string, body: unknown) =>
      f.iam.handler(
        new Request(`${origin}/api/iam/${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-better-iam': '1', origin },
          body: JSON.stringify(body),
        }),
      );
    const discovered = await call('domains/discover', { email: 'x@web.example' });
    expect(discovered.status).toBe(200);
    expect((await discovered.json()).data.tenantId).toBe(acme.tenantId);
    expect((await call('domains/discover', { email: 'nobody' })).status).toBe(400);
    expect((await call('domains/discover', { email: 'x@unknown.example' })).status).toBe(404);
    expect((await call('domains/list', { tenantId: acme.tenantId })).status).toBe(401);

    // A member without iam:domains:* cannot manage domains.
    const member = await f.iam.api.identities.create(acme.credential, {
      tenantId: acme.tenantId,
      email: 'member@acme.test',
      name: 'Member',
      password: 'a strong member password',
    });
    expect(member.id).toBeDefined();
    const signedIn = await f.iam.api.auth.signIn({
      tenantId: acme.tenantId,
      email: 'member@acme.test',
      password: 'a strong member password',
    });
    if (!('token' in signedIn)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.domains.add(
        { token: signedIn.token },
        { tenantId: acme.tenantId, domain: 'x.example' },
      ),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      f.iam.api.domains.list({ token: signedIn.token }, { tenantId: acme.tenantId }),
    ).rejects.toMatchObject({ status: 403 });
  });
});
