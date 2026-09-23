import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, assertionKey, verifyAssertion } from '@better-iam/server';
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

const SECRET = 'assertions-test-secret-with-at-least-32-characters';

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: SECRET,
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
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
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const credential = { token: session.token };
  const created = await iam.api.tenants.create(credential, {
    parentId: root.tenant.id,
    name: 'Acme',
    type: 'organization',
    ownerEmail: 'owner@acme.test',
  });
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
  return {
    iam,
    tenantId: created.tenant.id,
    owner,
    ownerCredential: { token: owner.token },
    now: () => clock,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('stateless assertions', () => {
  it('issues signed assertions under iam:assertions:create and verifies them offline', async () => {
    const f = await fixture();
    const key = f.iam.assertionKey();
    expect(key).toBe(assertionKey(SECRET));
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const team = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    await f.iam.api.groups.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: team.id,
      identityId: alice.id,
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    // Members need an explicit grant per audience.
    await expect(
      f.iam.api.assertions.issue(
        { token: login.token },
        { tenantId: f.tenantId, audience: 'billing' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Billing caller',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:assertions:create'], resources: ['iam/billing'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await expect(
      f.iam.api.assertions.issue(
        { token: login.token },
        { tenantId: f.tenantId, audience: 'reports' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const issued = await f.iam.api.assertions.issue(
      { token: login.token },
      { tenantId: f.tenantId, audience: 'billing', claims: { plan: 'pro' } },
    );
    expect(issued.token.split('.')).toHaveLength(3);
    expect(issued.claims).toMatchObject({
      iss: 'http://localhost:3000',
      sub: alice.id,
      aud: 'billing',
      tid: f.tenantId,
      kind: 'user',
      mfa: false,
      method: 'password',
      name: 'Alice',
      email: 'alice@acme.test',
      roles: [role.id],
      groups: [team.id],
      ext: { plan: 'pro' },
    });
    expect(issued.claims.exp - issued.claims.iat).toBe(300);
    expect(issued.expiresAt).toBe(issued.claims.exp * 1000);
    // Offline verification with the derived key, audience, and issuer.
    const verified = verifyAssertion(issued.token, {
      key,
      audience: 'billing',
      issuer: 'http://localhost:3000',
      now: f.now(),
    });
    expect(verified.sub).toBe(alice.id);
    for (const [options, message] of [
      [{ key, audience: 'reports', now: f.now() }, 'Audience mismatch'],
      [{ key, audience: 'billing', issuer: 'https://other', now: f.now() }, 'Issuer mismatch'],
      [
        {
          key: assertionKey('another-secret-with-at-least-32-characters!!'),
          audience: 'billing',
          now: f.now(),
        },
        'Invalid signature',
      ],
      [{ key, audience: 'billing', now: f.now() + 400_000 }, 'Assertion expired'],
      [{ key: 'nope', audience: 'billing', now: f.now() }, 'Invalid verification key'],
    ] as const)
      expect(() => verifyAssertion(issued.token, options)).toThrow(message);
    const [head, body, signature] = issued.token.split('.') as [string, string, string];
    const tampered = Buffer.from(
      JSON.stringify({
        ...JSON.parse(Buffer.from(body, 'base64url').toString()),
        roles: ['owner'],
      }),
    ).toString('base64url');
    expect(() =>
      verifyAssertion(`${head}.${tampered}.${signature}`, {
        key,
        audience: 'billing',
        now: f.now(),
      }),
    ).toThrow('Invalid signature');
    expect(() => verifyAssertion('garbage', { key, audience: 'billing' })).toThrow(
      'Malformed assertion',
    );
    // Validation of audience, lifetime, and claims; the owner may assert for any audience.
    await expect(
      f.iam.api.assertions.issue(f.ownerCredential, {
        tenantId: f.tenantId,
        audience: 'bad audience',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.assertions.issue(f.ownerCredential, {
        tenantId: f.tenantId,
        audience: 'x',
        ttlSeconds: 5,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.assertions.issue(f.ownerCredential, {
        tenantId: f.tenantId,
        audience: 'x',
        claims: { sub: 'someone-else' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const short = await f.iam.api.assertions.issue(f.ownerCredential, {
      tenantId: f.tenantId,
      audience: 'reports',
      ttlSeconds: 60,
    });
    expect(short.claims.roles.length).toBe(1);
    expect(short.claims.sub).toBe(f.owner.identity.id);
    f.advance(61_000 + 30_000);
    expect(() => verifyAssertion(short.token, { key, audience: 'reports', now: f.now() })).toThrow(
      'Assertion expired',
    );
    // Issuance is audited; the key is never part of the HTTP surface.
    const events = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'iam:assertions:create',
    });
    expect(
      events.some((event) => event.resourceId === 'billing' && event.outcome === 'allow'),
    ).toBe(true);
    expect(events.some((event) => event.resourceId === 'reports' && event.outcome === 'deny')).toBe(
      true,
    );
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/assertions/issue', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${login.token}`,
        },
        body: JSON.stringify({ tenantId: f.tenantId, audience: 'billing' }),
      }),
    );
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { data: { token: string } };
    expect(
      verifyAssertion(payload.data.token, { key, audience: 'billing', now: f.now() }).sub,
    ).toBe(alice.id);
    const denied = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/assertions/assertionKey', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
        body: '{}',
      }),
    );
    expect(denied.status).toBe(404);
  });
});
