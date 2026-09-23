import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { Session } from '@better-iam/core';
import { generateTestKey } from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const hash = (token: string) => createHash('sha256').update(token).digest('hex');

describe('session privacy', () => {
  it('never returns a session token hash, directly or over HTTP', async () => {
    const f = await organizationFixture();
    const other = await f.ownerSignIn();
    const current = await f.ownerSignIn();
    const hashes = [hash(other.token), hash(current.token)];
    const direct = await f.iam.api.auth.getSession(current);
    const listed = await f.iam.api.auth.listSessions(current);
    expect(listed.length).toBeGreaterThanOrEqual(2);
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/auth/listSessions', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${current.token}`,
          'content-type': 'application/json',
          'x-better-iam': '1',
        },
        body: '{}',
      }),
    );
    expect(response.status).toBe(200);
    const overHttp = (await response.json()) as { data: Record<string, unknown>[] };
    for (const text of [JSON.stringify(direct), JSON.stringify(listed), JSON.stringify(overHttp)])
      for (const value of hashes) expect(text).not.toContain(value);
    for (const session of [direct.session, ...listed, ...overHttp.data]) {
      expect(session).not.toHaveProperty('tokenHash');
      expect(session).not.toHaveProperty('uniqueKey');
    }
  });

  it('keeps hashes, policies and authority ids out of every temporary-credential answer over HTTP', async () => {
    const f = await organizationFixture({
      sts: { jwt: { signingKeys: [generateTestKey('EdDSA', 'k1').privateJwk as never] } },
    });
    const post = async (path: string, body: unknown, token: string) => {
      const response = await f.iam.handler(
        new Request(`http://localhost:3000/api/iam/${path}`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
            'x-better-iam': '1',
          },
          body: JSON.stringify(body),
        }),
      );
      expect(response.status, path).toBe(200);
      return { path, text: await response.text() };
    };
    const readOnly = {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
    };
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    // An API key with scopes, so its session tokens carry a source policy and a credential authority.
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'svc',
    });
    const key = await f.iam.api.credentials.create(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: account.id,
      scopes: ['documents:read', 'iam:session-tokens:create'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: (
        await f.iam.api.roles.create(f.ownerCredential, {
          tenantId: f.tenantId,
          name: 'Token minter',
          permissions: ['iam:session-tokens:create'],
        })
      ).id,
      subjectType: 'identity',
      subjectId: account.id,
    });

    const answers: { path: string; text: string }[] = [];
    const issued: string[] = [];
    const issue = async (path: string, body: unknown, token: string) => {
      const answer = await post(path, body, token);
      answers.push(answer);
      const credential = (JSON.parse(answer.text) as { data: { token: string } }).data;
      expect(Object.keys(credential).sort()).toEqual(
        expect.arrayContaining([
          'expiresAt',
          'expiresIn',
          'format',
          'session',
          'token',
          'tokenType',
        ]),
      );
      issued.push(credential.token);
      return credential.token;
    };
    const owner = f.ownerCredential.token;
    const opaque = await issue('sts/getSessionToken', { policy: readOnly }, owner);
    const jwt = await issue(
      'sts/getSessionToken',
      { policy: readOnly, format: 'jwt', sessionName: 'jwt-cli' },
      owner,
    );
    const scoped = await issue('sts/getSessionToken', {}, key.token);
    const assumed = await issue(
      'roles/assume',
      { tenantId: f.tenantId, trustId: trust.id, policy: readOnly, sessionName: 'assumed' },
      owner,
    );
    // A scoped-down token may not assume roles (its policy bounds iam:roles:assume), an unscoped one may.
    const plain = await issue('sts/getSessionToken', { sessionName: 'plain' }, owner);
    expect((await f.iam.authenticate({ token: opaque })).session.kind).toBe('session-token');
    const fromToken = await issue(
      'roles/assume',
      { tenantId: f.tenantId, trustId: trust.id, format: 'jwt' },
      plain,
    );
    for (const token of [owner, key.token, ...issued])
      answers.push(await post('sts/getCallerIdentity', {}, token));
    answers.push(await post('roles/listSessions', { tenantId: f.tenantId }, owner));
    answers.push(
      await post('roles/listSessions', { tenantId: f.tenantId, trustId: trust.id }, owner),
    );
    answers.push(await post('auth/listSessions', {}, owner));
    answers.push(
      await post('identities/listSessions', { tenantId: f.tenantId, identityId: f.ownerId }, owner),
    );
    answers.push(
      await post(
        'identities/listSessions',
        { tenantId: f.tenantId, identityId: account.id },
        owner,
      ),
    );

    // Every stored hash of every live session, and every token hash, stays out of every answer.
    const stored = await f.iam.store.find<Session>('sessions', {});
    const secrets = new Set([
      ...stored.flatMap((session) => [session.tokenHash, session.uniqueKey ?? '']),
      ...[owner, key.token, ...issued].map(hash),
    ]);
    secrets.delete('');
    expect(stored.some((session) => session.sourcePolicy)).toBe(true);
    expect(stored.some((session) => session.credentialAuthorityId)).toBe(true);
    for (const { path, text } of answers) {
      for (const secret of secrets) expect(text, path).not.toContain(secret);
      expect(text, path).not.toMatch(/"(tokenHash|uniqueKey)"/);
    }
    // The allowlist projections (TemporaryCredential, CallerIdentity, RoleSessionSummary) never carry policies,
    // authority ids or the source session either.
    const projections = answers.filter(
      ({ path }) => path.startsWith('sts/') || path.startsWith('roles/'),
    );
    expect(projections).toHaveLength(issued.length * 2 + 2 + 2);
    for (const { path, text } of projections) {
      expect(text, path).not.toMatch(
        /"(policy|sourcePolicy|credentialAuthorityId|sourceAuthorityIds|sourceSessionId|statements)"/,
      );
    }
    // The role sessions really were listed.
    const listing = JSON.parse(answers.find(({ path }) => path === 'roles/listSessions')!.text) as {
      data: { id: string }[];
    };
    expect(listing.data).toHaveLength(2);
    expect(scoped).toMatch(/^biam_sts_/);
    expect(assumed).toMatch(/^biam_rol_/);
    expect(fromToken.split('.')).toHaveLength(3);
    expect(jwt.split('.')).toHaveLength(3);
  });
});
