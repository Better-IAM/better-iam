import { afterEach, describe, expect, it } from 'vitest';
import { readDelegationTokenClaims, type PolicyDocument } from '@better-iam/core';
import { encryptSecret, openSecret } from '@better-iam/auth';
import { verifyAssertion } from '@better-iam/server';
import { webIdentityConditions } from '../packages/server/src/web-identity.js';
import { verifyAssertionToken } from '@better-iam/next';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = (actions: string[], resources = ['*']): PolicyDocument => ({
  version: 1,
  statements: [{ effect: 'allow', actions, resources }],
});

describe('delegation token time checks', () => {
  const now = Date.now();
  const claims = {
    iss: 'https://iam.example',
    sub: 'usr_person',
    aud: 'https://api.example',
    jti: 'jti-1',
    tenant_id: 'ten_acme',
    delegation_id: 'dlg_1',
    act: { sub: 'agt_1' },
    iat: Math.floor(now / 1000) - 7200,
    nbf: Math.floor(now / 1000) - 7200,
    exp: Math.floor(now / 1000) - 7000,
  };
  const expected = { issuer: 'https://iam.example', audience: 'https://api.example', now };
  it('reject an expired token with the default tolerance', () => {
    expect(readDelegationTokenClaims(claims, expected)).toMatchObject({ rejected: 'expired' });
  });
  it('fail closed on a NaN or infinite tolerance or clock instead of accepting any token', () => {
    for (const bad of [
      { clockToleranceSeconds: Number.NaN },
      { clockToleranceSeconds: Number.POSITIVE_INFINITY },
      { clockToleranceSeconds: -1 },
      { clockToleranceSeconds: 301 },
      { now: Number.NaN },
    ])
      expect(() => readDelegationTokenClaims(claims, { ...expected, ...bad })).toThrow(TypeError);
  });
});

describe('assertion signatures', () => {
  it('accept only the canonical spelling of the signature', async () => {
    const f = await organizationFixture();
    const issued = await f.iam.api.assertions.issue(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      audience: 'billing',
    });
    const key = f.iam.assertionKey();
    const options = { key, audience: 'billing' };
    expect(verifyAssertion(issued.token, options).sub).toBe(f.ownerId);
    expect((await verifyAssertionToken(issued.token, options)).sub).toBe(f.ownerId);
    // A 32-byte MAC is 43 base64url characters: the last one carries two unused bits, so flipping them decodes to
    // the same bytes. Padding and appended junk decode the same way too.
    const [head, body, signature] = issued.token.split('.') as [string, string, string];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(signature.at(-1)!);
    const sibling = alphabet[last ^ 1]!;
    for (const variant of [
      `${signature.slice(0, -1)}${sibling}`,
      `${signature}=`,
      `${signature}==`,
    ]) {
      const token = `${head}.${body}.${variant}`;
      expect(() => verifyAssertion(token, options), variant).toThrow();
      await expect(verifyAssertionToken(token, options), variant).rejects.toThrow();
    }
  });

  it('refuse scoped API keys, as they refuse scoped session tokens', async () => {
    const f = await organizationFixture();
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'billing-caller',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Billing admin',
      permissions: ['iam:assertions:create', 'documents:write'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    const scoped = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
      scopes: ['iam:assertions:create'],
    });
    await expect(
      f.iam.api.assertions.issue(
        { token: scoped.token },
        { tenantId: f.tenantId, audience: 'billing' },
      ),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: 'Scoped credentials cannot obtain assertions',
    });
    const unscoped = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    const assertion = await f.iam.api.assertions.issue(
      { token: unscoped.token },
      { tenantId: f.tenantId, audience: 'billing' },
    );
    expect(assertion.claims.roles).toEqual([role.id]);
  });
});

describe('web identity subject pins', () => {
  it('refuse wildcards that would admit a whole platform or other owners', () => {
    for (const sub of ['*', '?epo:*', 'repo:*', 'repo:acme*', 'repo::*', 'r*'])
      expect(() => webIdentityConditions({ StringLike: { 'token.sub': sub } }), sub).toThrow(
        expect.objectContaining({ code: 'WEAK_TRUST_CONDITIONS' }),
      );
  });
  it('keep accepting owner- and workload-scoped pins', () => {
    for (const sub of [
      'repo:acme/*',
      'repo:acme/api:*',
      'repo:acme/api:ref:refs/heads/release-?',
      'project_path:acme/*',
      'system:serviceaccount:ci:*',
    ])
      expect(() => webIdentityConditions({ StringLike: { 'token.sub': sub } }), sub).not.toThrow();
    expect(() =>
      webIdentityConditions({ StringEquals: { 'token.sub': 'repo:acme/api:ref:refs/heads/main' } }),
    ).not.toThrow();
  });
});

describe('sealed values', () => {
  it('refuse truncated GCM tags and odd IV sizes', () => {
    const secret = 'sealing-secret-with-at-least-32-characters';
    const sealed = encryptSecret('top secret', secret, 'ctx');
    expect(openSecret(sealed, secret, 'ctx')).toEqual({ value: 'top secret', index: 0 });
    const [iv, tag, body] = sealed.split('.') as [string, string, string];
    const bytes = (part: string) => Buffer.from(part, 'base64url');
    for (const length of [4, 8, 12, 15]) {
      const truncated = bytes(tag).subarray(0, length).toString('base64url');
      expect(openSecret(`${iv}.${truncated}.${body}`, secret, 'ctx'), `${length}`).toBeUndefined();
    }
    const longIv = Buffer.concat([bytes(iv), Buffer.alloc(4)]).toString('base64url');
    expect(openSecret(`${longIv}.${tag}.${body}`, secret, 'ctx')).toBeUndefined();
  });
});

/**
 * Security review regressions (session e15e8e) for temporary credentials: sources that must not mint role sessions.
 */
describe('role assumption sources', () => {
  it('refuses a delegated agent session, even when its delegation covers iam:roles:assume', async () => {
    const f = await organizationFixture();
    const api = f.iam.api;
    const alice = await f.member('alice');
    const operator = await api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Operator',
      document: doc(['documents:*', 'iam:roles:assume']),
    });
    await api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: operator.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const target = await api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Target',
      permissions: ['documents:write'],
    });
    const trust = await api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: alice.id,
      roleId: target.id,
      requireMfa: false,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    // Alice herself may assume the role.
    const own = await api.roles.assume(aliceSession, { tenantId: f.tenantId, trustId: trust.id });
    expect(own.session.kind).toBe('role');

    const agent = await api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Ops agent',
      model: 'claude-sonnet-5',
    });
    const agentKey = {
      token: (await api.credentials.create(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: agent.id,
      })).token,
    };
    const delegation = await api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['iam:roles:assume'],
      expiresInSeconds: 3600,
    });
    const delegated = await api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(delegated.session.kind).toBe('delegated');
    await expect(
      api.roles.assume({ token: delegated.token }, { tenantId: f.tenantId, trustId: trust.id }),
    ).rejects.toMatchObject({
      code: 'CREDENTIAL_CHAINING_DISABLED',
      message: 'Delegated sessions cannot assume roles',
    });
    const roleSessions = await f.iam.store.find('sessions', { kind: 'role', identityId: alice.id });
    expect(roleSessions).toHaveLength(1);
  });
});
