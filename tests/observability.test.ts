import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type IamSpan } from '@better-iam/server';
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

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const spans: IamSpan[] = [];
  let explode = false;
  const iam = betterIam({
    database,
    secret: 'observability-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    observability: {
      onSpan(span) {
        spans.push(span);
        if (explode) throw new Error('metrics backend down');
      },
    },
    permissions: {
      resourceTypes: { folder: { managed: true, actions: ['folders:read'] } },
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
    spans,
    tenantId: created.tenant.id,
    ownerCredential: { token: owner.token },
    setExplode: (value: boolean) => {
      explode = value;
    },
  };
}

describe('observability spans', () => {
  it('reports operations, authorization queries, authentication calls, and HTTP requests with outcomes', async () => {
    const f = await fixture();
    f.spans.length = 0;
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const created = f.spans.find(
      (span) => span.kind === 'operation' && span.name === 'iam:identities:create',
    );
    expect(created).toMatchObject({ outcome: 'ok', tenantId: f.tenantId });
    expect(created!.durationMs).toBeGreaterThanOrEqual(0);
    // A denied operation, an unknown-tenant error, and a failed sign-in each classify differently.
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'auth',
      name: 'signIn',
      tenantId: f.tenantId,
      outcome: 'ok',
    });
    await expect(
      f.iam.api.groups.create({ token: login.token }, { tenantId: f.tenantId, name: 'Nope' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'operation',
      name: 'iam:groups:create',
      outcome: 'denied',
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.iam.api.groups.list(f.ownerCredential, { tenantId: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'operation',
      name: 'iam:groups:read',
      tenantId: 'missing',
      outcome: 'error',
      code: 'NOT_FOUND',
    });
    await expect(
      f.iam.api.auth.signIn({ tenantId: f.tenantId, email: 'alice@acme.test', password: 'wrong' }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'auth',
      name: 'signIn',
      outcome: 'denied',
      code: 'INVALID_CREDENTIALS',
    });
    // Advisory denials are `denied` spans that carry the decision reason.
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
    });
    const decision = await f.iam.authorize({
      token: login.token,
      tenantId: f.tenantId,
      action: 'folders:read',
      resource: { type: 'folder', id: 'plans' },
    });
    expect(decision.allowed).toBe(false);
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'authorize',
      name: 'folders:read',
      outcome: 'denied',
      code: 'ACCESS_DENIED',
    });
    await f.iam.authorizeMany({
      token: login.token,
      tenantId: f.tenantId,
      checks: [{ action: 'folders:read', resource: { type: 'folder', id: 'plans' } }],
    });
    expect(f.spans.at(-1)).toMatchObject({ kind: 'authorizeMany', outcome: 'ok' });
    await f.iam.listAccessible({
      token: login.token,
      tenantId: f.tenantId,
      action: 'folders:read',
      type: 'folder',
    });
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'listAccessible',
      name: 'folders:read',
      outcome: 'ok',
    });
    // HTTP spans wrap the dispatched call with the response status.
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/groups/create', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${login.token}`,
        },
        body: JSON.stringify({ tenantId: f.tenantId, name: 'Nope' }),
      }),
    );
    expect(response.status).toBe(403);
    expect(f.spans.at(-1)).toMatchObject({
      kind: 'http',
      name: 'groups/create',
      tenantId: f.tenantId,
      outcome: 'denied',
      status: 403,
    });
    expect(f.spans.at(-2)).toMatchObject({ kind: 'operation', name: 'iam:groups:create' });
    // A throwing span handler never affects the request.
    f.setExplode(true);
    expect(
      (
        await f.iam.api.identities.get(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: alice.id,
        })
      ).id,
    ).toBe(alice.id);
  });
});
