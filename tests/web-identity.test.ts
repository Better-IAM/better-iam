import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, PolicyDocument, Session } from '@better-iam/core';
import { betterIam, type BetterIamOptions } from '@better-iam/server';
import type {
  OidcProvider,
  PublicJwk,
  Role,
  Trust,
  WebIdentityReplay,
} from '../packages/server/src/models.js';
import {
  decodeTestJwt,
  generateTestKey,
  signTestJwt,
  tamperPayload,
  type SignTestJwtKey,
  type TestKey,
} from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/**
 * AssumeRoleWithWebIdentity end to end: web-identity trusts (`trust.create` with `kind: 'web-identity'`), the public
 * exchange (`sts.assumeRoleWithWebIdentity`, in process and over `iam.handler`), the uniform refusal, replay
 * protection, rate and session limits, audits, kill switches and revocation, network allowlists, key rotation, the
 * JWT format, and the administrators' dry run (`trust.evaluateWebIdentity`). External identity providers are played
 * with tests/support/jwt-keys.ts; keys are served as static `jwks` or through `sts.webIdentity.fetchJson`.
 */

const issuer = 'https://token.actions.example.test';
const audience = 'https://acme.example';
const subject = 'repo:acme/app:ref:refs/heads/main';
const rejectedBody = {
  error: { code: 'WEB_IDENTITY_REJECTED', message: 'The web identity token was not accepted' },
};
/** Reads everything; writes only when the session carries the expected web identity, name, tag and source identity. */
const deployer: PolicyDocument = {
  version: 1,
  statements: [
    { effect: 'allow', actions: ['documents:read'], resources: ['*'] },
    {
      effect: 'allow',
      actions: ['documents:write'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'principal.webIdentitySubject': subject,
          'principal.sessionName': 'ci-run',
          'principal.sessionTags.repo': 'acme/app',
          'principal.sourceIdentity': 'octocat',
        },
      },
    },
  ],
};

type StsOptions = NonNullable<BetterIamOptions['sts']>;
type WebIdentityOptions = NonNullable<StsOptions['webIdentity']>;

async function setup(options: { webIdentity?: WebIdentityOptions; sts?: StsOptions } = {}) {
  const f = await organizationFixture({
    sts: { ...options.sts, webIdentity: { enabled: true, ...options.webIdentity } },
  });
  const rsa = generateTestKey('RS256', 'rsa-1');
  const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'GitHub Actions',
    issuer,
    audiences: [audience],
    jwks: { keys: [rsa.publicJwk as PublicJwk] },
  });
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'ci',
  });
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Deployer',
    document: deployer,
  });
  const trust = await f.iam.api.trust.create(f.ownerCredential, {
    tenantId: f.tenantId,
    kind: 'web-identity',
    providerId: provider.id,
    serviceAccountId: account.id,
    roleId: role.id,
    conditions: { StringEquals: { 'token.sub': subject, 'token.repository_owner': 'acme' } },
    tagClaims: { repo: 'token.repository' },
    sourceIdentityClaim: 'token.actor',
  });
  /** A fresh token from the test IdP (current iat, five-minute lifetime, unique jti). */
  const token = (
    claims: Record<string, unknown> = {},
    header: Record<string, unknown> = {},
    key: SignTestJwtKey = rsa,
  ) => {
    const iat = Math.floor(f.now() / 1000);
    return signTestJwt(
      key,
      {
        iss: issuer,
        aud: audience,
        sub: subject,
        iat,
        exp: iat + 300,
        jti: randomUUID(),
        repository: 'acme/app',
        repository_owner: 'acme',
        actor: 'octocat',
        ...claims,
      },
      header,
    );
  };
  const exchange = (webIdentityToken: string, extra: Record<string, unknown> = {}) =>
    f.iam.api.sts.assumeRoleWithWebIdentity({
      tenantId: f.tenantId,
      trustId: trust.id,
      webIdentityToken,
      sessionName: 'ci-run',
      ...extra,
    });
  /** The public route over the Fetch handler, as a workload would call it. */
  const http = (body: Record<string, unknown>) =>
    f.iam.handler(
      new Request(
        `${f.iam.endpoint.origin}${f.iam.endpoint.basePath}/sts/assumeRoleWithWebIdentity`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
          body: JSON.stringify(body),
        },
      ),
    );
  const works = async (credential: string) => {
    try {
      await f.iam.authenticate({ token: credential });
      return true;
    } catch {
      return false;
    }
  };
  const allowed = async (credential: string, action: string) =>
    (
      await f.iam.authorize({
        token: credential,
        tenantId: f.tenantId,
        action,
        resource: { type: 'document', id: 'release-notes' },
      })
    ).allowed;
  /** The tenant's events for `action` in the order they were recorded; the store returns them by (random) id. */
  const audits = async (action = 'role:assumed-with-web-identity') =>
    (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId }))
      .filter((event) => event.action === action)
      .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
  return { f, rsa, provider, account, role, trust, token, exchange, http, works, allowed, audits };
}
type Setup = Awaited<ReturnType<typeof setup>>;

/** A second provider (another issuer and key) with a trust on the same role. */
async function secondProvider(
  s: Setup,
  key: TestKey,
  secondIssuer = 'https://gitlab.example.test',
) {
  const provider = await s.f.iam.api.oidcProviders.create(s.f.ownerCredential, {
    tenantId: s.f.tenantId,
    name: 'GitLab',
    issuer: secondIssuer,
    audiences: [audience],
    jwks: { keys: [key.publicJwk as PublicJwk] },
  });
  const trust = await s.f.iam.api.trust.create(s.f.ownerCredential, {
    tenantId: s.f.tenantId,
    kind: 'web-identity',
    providerId: provider.id,
    serviceAccountId: s.account.id,
    roleId: s.role.id,
    conditions: { StringEquals: { 'token.sub': subject } },
  });
  return { provider, trust };
}

/**
 * A member holding the given IAM permissions through a role (with a delegated grant authority), and a way to sign
 * in again. Returns the binding so a test can take the permissions away.
 */
async function administrator(f: Setup['f'], name: string, permissions: string[]) {
  const identity = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} role`,
    permissions,
  });
  const binding = await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  await f.iam.api.authorities.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: identity.id,
    ceiling: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
  });
  const signIn = async () => ({ token: (await f.signIn(name)).token });
  return { identity, binding, signIn };
}

describe('web-identity trusts', () => {
  it('bind a service account only for callers with authority over it (iam:identities:update)', async () => {
    const s = await setup();
    const { f } = s;
    const trustee = await administrator(f, 'trustee', [
      'iam:trust:create',
      'iam:trust:update',
      'iam:trust:read',
    ]);
    const input = {
      tenantId: f.tenantId,
      kind: 'web-identity' as const,
      providerId: s.provider.id,
      serviceAccountId: s.account.id,
      roleId: s.role.id,
      conditions: { StringEquals: { 'token.sub': subject } },
    };
    // Trust permissions alone would let the trustee act as any service account of the tenant.
    await expect(f.iam.api.trust.create(await trustee.signIn(), input)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      status: 403,
      message:
        'Binding a service account to a web-identity trust requires iam:identities:update on it',
    });
    const denials = async (action: string) =>
      (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
        (event) =>
          event.action === action &&
          event.outcome === 'deny' &&
          event.actorId === trustee.identity.id,
      );
    expect(await denials('iam:trust:create')).toHaveLength(1);
    expect(
      (await f.iam.store.find<Trust>('trusts', { tenantId: f.tenantId })).filter(
        (trust) => trust.createdBy === trustee.identity.id,
      ),
    ).toEqual([]);

    // With authority over the account (the permission that manages service accounts), the trust is created.
    const manager = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Service account manager',
      permissions: ['iam:identities:update'],
    });
    const managing = await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: manager.id,
      subjectType: 'identity',
      subjectId: trustee.identity.id,
    });
    const created = await f.iam.api.trust.create(await trustee.signIn(), input);
    expect(created).toMatchObject({ kind: 'web-identity', sourceIdentityId: s.account.id });
    const target = { tenantId: f.tenantId, trustId: created.id };
    expect(
      (await f.iam.api.trust.update(await trustee.signIn(), { ...target, description: 'CI' }))
        .description,
    ).toBe('CI');

    // Without it again, changing the trust is refused too (and audited), while root still may.
    await f.iam.api.bindings.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      bindingId: managing.id,
    });
    await expect(
      f.iam.api.trust.update(await trustee.signIn(), {
        ...target,
        conditions: { StringLike: { 'token.sub': 'repo:acme/*' } },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await denials('iam:trust:update')).toHaveLength(1);
    expect((await f.iam.store.get<Trust>('trusts', created.id))!.conditions).toEqual(
      input.conditions,
    );
    expect(
      (await f.iam.api.trust.update(f.rootCredential, { ...target, description: 'Deploys' }))
        .description,
    ).toBe('Deploys');
  });

  it('are created by tenant administrators with the web-identity defaults', async () => {
    const s = await setup();
    const { f, trust } = s;
    expect(trust).toEqual({
      id: trust.id,
      tenantId: f.tenantId,
      kind: 'web-identity',
      sourceTenantId: f.tenantId,
      sourceIdentityId: s.account.id,
      roleId: s.role.id,
      requireMfa: false,
      requiresExternalId: false,
      revoked: false,
      ceiling: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
      passSourceAttributes: true,
      providerId: s.provider.id,
      conditions: { StringEquals: { 'token.sub': subject, 'token.repository_owner': 'acme' } },
      tagClaims: { repo: 'token.repository' },
      sourceIdentityClaim: 'token.actor',
      authorityId: s.provider.authorityId,
      createdAt: f.now(),
      createdBy: f.ownerId,
      updatedAt: f.now(),
    });
    // UUIDv4 ids, so trust ids cannot be guessed.
    expect(trust.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('validates conditions, the role, the provider, the service account and the fields', async () => {
    const s = await setup();
    const { f } = s;
    const base = {
      tenantId: f.tenantId,
      kind: 'web-identity' as const,
      providerId: s.provider.id,
      serviceAccountId: s.account.id,
      roleId: s.role.id,
      conditions: { StringEquals: { 'token.sub': subject } },
    };
    const create = (extra: Record<string, unknown>) =>
      f.iam.api.trust.create(f.ownerCredential, { ...base, ...extra } as never);
    for (const conditions of [
      { StringLike: { 'token.sub': '*' } },
      { StringLike: { 'token.sub': '?epo:*' } },
      { StringEquals: { 'token.repository': 'acme/app' } },
      { StringNotEquals: { 'token.sub': 'repo:evil' } },
    ])
      await expect(create({ conditions })).rejects.toMatchObject({
        code: 'WEAK_TRUST_CONDITIONS',
      });
    for (const extra of [
      { conditions: { StringEquals: { sub: subject } } },
      { conditions: { StringEquals: { 'token.sub': '${principal.id}' } } },
      { conditions: undefined },
      { tagClaims: { 'bad-key': 'token.repository' } },
      { tagClaims: { repo: 'repository' } },
      { sourceIdentityClaim: 'actor' },
      { maxSessionSeconds: 7200 },
      { passSourceAttributes: 'yes' },
      { sourceTenantId: f.tenantId },
      { sourceIdentityId: s.account.id },
      { requireMfa: false },
      { externalId: 'shared' },
      { allowedTagKeys: ['team'] },
      { sourceIdentityMode: 'optional' },
      { providerId: undefined },
    ])
      await expect(create(extra)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Web-only fields on an identity trust are refused as well.
    await expect(
      f.iam.api.trust.create(f.rootCredential, {
        tenantId: f.tenantId,
        sourceTenantId: f.tenantId,
        sourceIdentityId: f.ownerId,
        roleId: s.role.id,
        providerId: s.provider.id,
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const ownerRole = (await f.iam.store.find<Role>('roles', { tenantId: f.tenantId })).find(
      (role) => role.protected,
    )!;
    await expect(create({ roleId: ownerRole.id })).rejects.toMatchObject({
      code: 'PROTECTED_RESOURCE',
    });
    await expect(create({ providerId: randomUUID() })).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(create({ serviceAccountId: f.ownerId })).rejects.toMatchObject({
      code: 'INVALID_IDENTITY',
      message: 'Web-identity trusts require an active service account',
    });
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: s.account.id,
      status: 'disabled',
    });
    await expect(create({})).rejects.toMatchObject({ code: 'INVALID_IDENTITY' });
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: s.account.id,
      status: 'active',
    });
    // Tenant-managed, but only with the permission and recent authentication.
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    await expect(f.iam.api.trust.create(alice, base)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    f.advance(6 * 60_000);
    await expect(f.iam.api.trust.create(f.ownerCredential, base)).rejects.toMatchObject({
      code: 'RECENT_AUTH_REQUIRED',
    });
    expect((await f.iam.api.trust.create(await f.ownerSignIn(), base)).kind).toBe('web-identity');
  });

  it('need sts.webIdentity.enabled to be created, evaluated or updated, but not revoked', async () => {
    const f = await organizationFixture();
    const input = {
      tenantId: f.tenantId,
      kind: 'web-identity' as const,
      providerId: randomUUID(),
      serviceAccountId: randomUUID(),
      roleId: randomUUID(),
      conditions: { StringEquals: { 'token.sub': subject } },
    };
    await expect(f.iam.api.trust.create(f.ownerCredential, input)).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
      status: 403,
    });
    await expect(
      f.iam.api.sts.assumeRoleWithWebIdentity({
        tenantId: f.tenantId,
        trustId: randomUUID(),
        webIdentityToken: 'a.b.c',
        sessionName: 'ci-run',
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // A web trust stored while the feature was on.
    const now = f.now();
    const seeded: Trust = {
      id: randomUUID(),
      tenantId: f.tenantId,
      kind: 'web-identity',
      sourceTenantId: f.tenantId,
      sourceIdentityId: randomUUID(),
      roleId: randomUUID(),
      requireMfa: false,
      revoked: false,
      providerId: randomUUID(),
      conditions: input.conditions,
      createdAt: now,
      updatedAt: now,
    };
    await f.iam.store.transaction((tx) => tx.insert('trusts', seeded));
    const target = { tenantId: f.tenantId, trustId: seeded.id };
    await expect(
      f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, {
        ...target,
        webIdentityToken: 'a.b.c',
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    await expect(
      f.iam.api.trust.update(f.rootCredential, { ...target, description: 'x' }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // Revoking only removes access, so it works with the feature off and deletes the trust's sessions: switching
    // the feature back on cannot revive them.
    const session: Session = {
      id: randomUUID(),
      tenantId: f.tenantId,
      identityId: seeded.sourceIdentityId,
      originalIdentityId: seeded.sourceIdentityId,
      roleId: seeded.roleId,
      trustId: seeded.id,
      kind: 'role',
      tokenHash: `hash-${randomUUID()}`,
      createdAt: now,
      lastSeenAt: now,
      authenticatedAt: now,
      expiresAt: now + 900_000,
      mfa: false,
      webIdentity: { providerId: seeded.providerId!, issuer, subject },
    };
    await f.iam.store.transaction((tx) =>
      tx.insert('sessions', { ...session, uniqueKey: session.tokenHash } as never),
    );
    expect(await f.iam.api.trust.revoke(f.rootCredential, target)).toMatchObject({
      id: seeded.id,
      revoked: true,
    });
    expect((await f.iam.store.get<Trust>('trusts', seeded.id))!.revoked).toBe(true);
    expect(await f.iam.store.get('sessions', session.id)).toBeUndefined();
  });
});

describe('sts.assumeRoleWithWebIdentity', () => {
  it('issues a role session for RSA tokens from static keys, visible to policies', async () => {
    const s = await setup();
    const { f } = s;
    const external = s.token();
    const credential = await s.exchange(external);
    expect(credential).toEqual({
      token: expect.stringMatching(/^biam_rol_[A-Za-z0-9_-]{49}$/),
      tokenType: 'Bearer',
      format: 'opaque',
      expiresAt: f.now() + 900_000,
      expiresIn: 900,
      session: {
        id: expect.any(String),
        tenantId: f.tenantId,
        kind: 'role',
        identityId: s.account.id,
        expiresAt: f.now() + 900_000,
        mfa: false,
        roleId: s.role.id,
        trustId: s.trust.id,
        sessionName: 'ci-run',
        sourceIdentity: 'octocat',
      },
      webIdentity: { providerId: s.provider.id, issuer, subject },
    });
    const row = (await f.iam.store.get<Session>('sessions', credential.session.id))!;
    expect(row).toMatchObject({
      kind: 'role',
      identityId: s.account.id,
      originalIdentityId: s.account.id,
      credentialAuthorityId: s.trust.authorityId,
      authenticatedAt: f.now(),
      sessionTags: { repo: 'acme/app' },
      webIdentity: { providerId: s.provider.id, issuer, subject },
    });
    expect(row.sourceSessionId).toBeUndefined();
    expect(row.sourceTenantId).toBeUndefined();
    expect(row.mfaAuthenticatedAt).toBeUndefined();

    expect(await s.allowed(credential.token, 'documents:read')).toBe(true);
    expect(await s.allowed(credential.token, 'documents:write')).toBe(true);
    expect(await f.iam.api.sts.getCallerIdentity({ token: credential.token })).toMatchObject({
      identityId: s.account.id,
      sessionKind: 'role',
      sessionName: 'ci-run',
      sourceIdentity: 'octocat',
      sessionTags: { repo: 'acme/app' },
      webIdentity: { providerId: s.provider.id, issuer, subject },
    });
    // Another session name no longer satisfies the write condition; a scope-down policy bounds the session.
    const renamed = await s.exchange(s.token(), { sessionName: 'nightly' });
    expect(await s.allowed(renamed.token, 'documents:read')).toBe(true);
    expect(await s.allowed(renamed.token, 'documents:write')).toBe(false);
    const scoped = await s.exchange(s.token(), {
      durationSeconds: 3600,
      policy: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:write'], resources: ['*'] }],
      },
    });
    expect(scoped.expiresIn).toBe(3600);
    expect(await s.allowed(scoped.token, 'documents:read')).toBe(false);
    expect(await s.allowed(scoped.token, 'documents:write')).toBe(true);
  });

  it('verifies EC tokens with keys discovered and fetched through sts.webIdentity.fetchJson', async () => {
    const ec = generateTestKey('ES256', 'ec-1');
    const gitlab = 'https://gitlab.example.test';
    const fetched: string[] = [];
    const s = await setup({
      webIdentity: {
        fetchJson: async (url) => {
          fetched.push(url.href);
          if (url.href === `${gitlab}/.well-known/openid-configuration`)
            return { issuer: gitlab, jwks_uri: `${gitlab}/oauth/discovery/keys` };
          if (url.href === `${gitlab}/oauth/discovery/keys`) return { keys: [ec.publicJwk] };
          throw new Error(`unexpected fetch ${url.href}`);
        },
      },
    });
    const provider = await s.f.iam.api.oidcProviders.create(s.f.ownerCredential, {
      tenantId: s.f.tenantId,
      name: 'GitLab',
      issuer: gitlab,
      audiences: [audience],
    });
    // Nothing is fetched when a provider is created.
    expect(fetched).toEqual([]);
    const trust = await s.f.iam.api.trust.create(s.f.ownerCredential, {
      tenantId: s.f.tenantId,
      kind: 'web-identity',
      providerId: provider.id,
      serviceAccountId: s.account.id,
      roleId: s.role.id,
      conditions: { StringLike: { 'token.sub': 'project_path:acme/*' } },
    });
    const iat = Math.floor(s.f.now() / 1000);
    const claims = { iss: gitlab, aud: audience, sub: 'project_path:acme/app:ref:main', iat };
    const credential = await s.f.iam.api.sts.assumeRoleWithWebIdentity({
      tenantId: s.f.tenantId,
      trustId: trust.id,
      webIdentityToken: signTestJwt(ec, { ...claims, exp: iat + 300, jti: randomUUID() }),
      sessionName: 'pipeline-42',
    });
    expect(credential.webIdentity).toEqual({
      providerId: provider.id,
      issuer: gitlab,
      subject: 'project_path:acme/app:ref:main',
    });
    expect(await s.works(credential.token)).toBe(true);
    expect(fetched).toEqual([
      `${gitlab}/.well-known/openid-configuration`,
      `${gitlab}/oauth/discovery/keys`,
    ]);
    // Cached: the next token fetches nothing.
    await s.f.iam.api.sts.assumeRoleWithWebIdentity({
      tenantId: s.f.tenantId,
      trustId: trust.id,
      webIdentityToken: signTestJwt(ec, { ...claims, exp: iat + 300, jti: randomUUID() }),
      sessionName: 'pipeline-43',
    });
    expect(fetched).toHaveLength(2);
  });

  it('answers every refusal with the same body over HTTP and never sets a cookie', async () => {
    const s = await setup();
    const { f } = s;
    const gitlabKey = generateTestKey('RS256', 'gitlab-1');
    const disabled = await secondProvider(s, gitlabKey);
    await f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: disabled.provider.id,
      enabled: false,
    });
    const revoked = await f.iam.api.trust.create(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'web-identity',
      providerId: s.provider.id,
      serviceAccountId: s.account.id,
      roleId: s.role.id,
      conditions: { StringEquals: { 'token.sub': subject } },
    });
    await f.iam.api.trust.revoke(f.ownerCredential, { tenantId: f.tenantId, trustId: revoked.id });

    const now = Math.floor(f.now() / 1000);
    const request = (webIdentityToken: string, extra: Record<string, unknown> = {}) => ({
      tenantId: f.tenantId,
      trustId: s.trust.id,
      webIdentityToken,
      sessionName: 'ci-run',
      ...extra,
    });
    const good = s.token();
    const accepted = await s.http(request(good));
    expect(accepted.status).toBe(200);
    expect(accepted.headers.get('set-cookie')).toBeNull();
    const { data: body } = (await accepted.json()) as {
      data: { token: string; webIdentity: unknown };
    };
    expect(body.token).toMatch(/^biam_rol_/);
    expect(body.webIdentity).toEqual({ providerId: s.provider.id, issuer, subject });
    expect(await s.works(body.token)).toBe(true);

    const failures: Record<string, Record<string, unknown>> = {
      audience: request(s.token({ aud: 'https://other.example' })),
      issuer: request(s.token({ iss: 'https://evil.example.test' })),
      expired: request(s.token({ iat: now - 1000, exp: now - 100 })),
      lifetime: request(s.token({ exp: now + 7200 })),
      age: request(s.token({ iat: now - 4000, exp: now + 60 })),
      hs256: request(s.token({}, {}, { alg: 'HS256', secret: 'shared-secret' })),
      none: request(s.token({}, {}, { alg: 'none' })),
      unknownKid: request(s.token({}, { kid: 'rotated-away' })),
      foreignKey: request(s.token({}, {}, generateTestKey('RS256', 'rsa-1'))),
      typ: request(s.token({}, { typ: 'at+jwt' })),
      ownSessionTyp: request(s.token({}, { typ: 'biam-session+jwt' })),
      missingSub: request(s.token({ sub: undefined })),
      forged: request(tamperPayload(s.token(), { sub: 'repo:acme/app:ref:refs/heads/evil' })),
      conditions: request(s.token({ sub: 'repo:acme/other:ref:refs/heads/main' })),
      sourceIdentity: request(s.token({ actor: 'not valid!' })),
      replay: request(good),
      unknownTrust: request(s.token(), { trustId: randomUUID() }),
      otherTenant: request(s.token(), { tenantId: f.root.tenant.id }),
      revokedTrust: request(s.token(), { trustId: revoked.id }),
      disabledProvider: request(s.token({ iss: 'https://gitlab.example.test' }, {}, gitlabKey), {
        trustId: disabled.trust.id,
      }),
    };
    for (const [name, input] of Object.entries(failures)) {
      const response = await s.http(input);
      expect({ name, status: response.status, body: await response.json() }).toEqual({
        name,
        status: 403,
        body: rejectedBody,
      });
      expect(response.headers.get('set-cookie')).toBeNull();
    }
    // Shape errors are the only specific answers before the rate limit and lookup.
    const malformed = await s.http(request('not-a-jwt'));
    expect(malformed.status).toBe(400);
    expect(((await malformed.json()) as typeof rejectedBody).error.code).toBe('INVALID_INPUT');
    const unnamed = await s.http(request(s.token(), { sessionName: 'x' }));
    expect(((await unnamed.json()) as typeof rejectedBody).error.code).toBe('INVALID_INPUT');

    // Denials are audited with their reason once the trust resolved; claims only when the signature verified.
    const denials = (await s.audits()).filter((event) => event.outcome === 'deny');
    const reasons = denials.map((event) => event.metadata?.reason);
    for (const reason of [
      'audience',
      'issuer',
      'expired',
      'lifetime',
      'too-old',
      'algorithm',
      'unknown-key',
      'signature',
      'type',
      'claims',
      'conditions',
      'source-identity',
      'replay',
    ])
      expect(reasons).toContain(reason);
    for (const event of denials) {
      expect(event.resourceId).toBe(s.role.id);
      expect(event.actorId).toBe(s.account.id);
      expect(event.metadata).toMatchObject({ trustId: s.trust.id, providerId: s.provider.id });
      const verified = ['conditions', 'source-identity', 'replay'].includes(
        event.metadata!.reason as string,
      );
      expect(event.metadata!.subject !== undefined).toBe(verified);
    }
    expect(denials.find((event) => event.metadata?.reason === 'replay')?.metadata).toMatchObject({
      issuer,
      subject,
    });
    // Unknown, foreign, revoked and disabled-provider trusts leave no audit trail.
    expect(denials.map((event) => event.metadata?.trustId)).not.toContain(revoked.id);
    expect(denials.map((event) => event.metadata?.trustId)).not.toContain(disabled.trust.id);
    expect(denials).toHaveLength(Object.keys(failures).length - 4);
  });

  it('audits issuance and never stores the raw token anywhere', async () => {
    const s = await setup();
    const { f } = s;
    const external = s.token();
    const credential = await s.exchange(external);
    await expect(s.exchange(external)).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    const [allow] = (await s.audits()).filter((event) => event.outcome === 'allow');
    expect(allow).toMatchObject({
      tenantId: f.tenantId,
      actorId: s.account.id,
      resourceId: s.role.id,
      metadata: {
        trustId: s.trust.id,
        providerId: s.provider.id,
        issuer,
        subject,
        durationSeconds: 900,
        format: 'opaque',
        tagKeys: ['repo'],
      },
      sessionContext: {
        sessionId: credential.session.id,
        kind: 'role',
        roleId: s.role.id,
        trustId: s.trust.id,
        sessionName: 'ci-run',
        sourceIdentity: 'octocat',
        webIdentityProviderId: s.provider.id,
        webIdentitySubject: subject,
      },
    });
    const collections = await f.iam.store.collections!();
    expect(collections).toContain('webIdentityReplays');
    const signature = external.split('.')[2]!;
    for (const collection of collections) {
      const dump = JSON.stringify(await f.iam.store.find(collection));
      expect({ collection, external: dump.includes(external) }).toEqual({
        collection,
        external: false,
      });
      expect(dump.includes(signature)).toBe(false);
      expect(dump.includes(credential.token)).toBe(false);
    }
  });

  it('redeems a token once, unless the provider turns replay protection off', async () => {
    const s = await setup();
    const { f } = s;
    const external = s.token();
    // A refusal after verification rolls back, so the token is not burned.
    await expect(s.exchange(external, { durationSeconds: 7200 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(s.exchange(external, { format: 'jwt' })).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
    });
    expect(await f.iam.store.find('webIdentityReplays')).toEqual([]);
    await s.exchange(external);
    await expect(s.exchange(external)).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    const { payload } = decodeTestJwt(external);
    const [replay] = await f.iam.store.find<WebIdentityReplay>('webIdentityReplays');
    expect(replay).toEqual({
      id: expect.stringMatching(/^[0-9a-f]{64}$/),
      tenantId: f.tenantId,
      providerId: s.provider.id,
      // The token's exp plus the largest clock tolerance a provider may have (120 s), so it outlives the acceptance
      // window even if the provider's tolerance is raised later.
      expiresAt: (payload.exp as number) * 1000 + 120_000,
    });
    // Tokens without a jti are keyed by their signed content (header.payload).
    const anonymous = s.token({ jti: undefined });
    await s.exchange(anonymous);
    await expect(s.exchange(anonymous)).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    // A different spelling of the same signature (unused trailing base64url bits) is still the same token.
    // (A distinct claim: without a jti, identical claims at the same clock are the same signed content.)
    const fresh = s.token({ jti: undefined, run_id: 'second' });
    const signature = fresh.slice(fresh.lastIndexOf('.') + 1);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const respelled = `${signature.slice(0, -1)}${alphabet[alphabet.indexOf(signature.slice(-1)) ^ 1]}`;
    expect(Buffer.from(respelled, 'base64url')).toEqual(Buffer.from(signature, 'base64url'));
    const variant = `${fresh.slice(0, fresh.lastIndexOf('.') + 1)}${respelled}`;
    expect(variant).not.toBe(fresh);
    await s.exchange(variant);
    await expect(s.exchange(fresh)).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    const replayDenials = (
      await f.iam.store.find<{ action: string; metadata?: Record<string, unknown> }>('audit')
    ).filter((event) => event.metadata?.reason === 'replay');
    expect(replayDenials.length).toBeGreaterThanOrEqual(2);

    await f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: s.provider.id,
      replayProtection: 'off',
    });
    const reusable = s.token();
    const first = await s.exchange(reusable);
    const second = await s.exchange(reusable);
    expect(first.session.id).not.toBe(second.session.id);
    // One record each for `external`, `anonymous` and the re-spelled `fresh`; none while protection is off.
    expect(await f.iam.store.find('webIdentityReplays')).toHaveLength(3);
  });

  it('counts exchanges per client address when one is known, so junk from one source cannot lock a trust', async () => {
    const s = await setup({ webIdentity: { maxExchangesPerWindow: 3 } });
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      s.f.iam.auth.withClient({ ip, userAgent: 'ci' }, fn);
    // An attacker who knows the (public) trust id posts junk until its own budget is gone.
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(from('198.51.100.66', () => s.exchange(s.token({ aud: 'wrong' })))).rejects.toMatchObject(
        { code: 'WEB_IDENTITY_REJECTED' },
      );
    await expect(from('198.51.100.66', () => s.exchange(s.token()))).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // The real workload, from its own address, still exchanges.
    expect((await from('203.0.113.9', () => s.exchange(s.token()))).session.kind).toBe('role');
  });

  it('counts exchanges per trust before any lookup (RATE_LIMITED)', async () => {
    const s = await setup({ webIdentity: { maxExchangesPerWindow: 3 } });
    await s.exchange(s.token());
    await expect(s.exchange(s.token({ aud: 'wrong' }))).rejects.toMatchObject({
      code: 'WEB_IDENTITY_REJECTED',
    });
    await s.exchange(s.token());
    await expect(s.exchange(s.token())).rejects.toMatchObject({
      code: 'RATE_LIMITED',
      status: 429,
    });
    // Unknown trusts are counted the same way, so the limit reveals nothing either.
    const unknown = randomUUID();
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(s.exchange(s.token(), { trustId: unknown })).rejects.toMatchObject({
        code: 'WEB_IDENTITY_REJECTED',
      });
    await expect(s.exchange(s.token(), { trustId: unknown })).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
  });

  it('caps live sessions per trust (LIMIT_EXCEEDED) without burning the token', async () => {
    const s = await setup({ webIdentity: { maxSessionsPerTrust: 2 } });
    const { f } = s;
    await s.exchange(s.token());
    await s.exchange(s.token());
    const third = s.token();
    await expect(s.exchange(third)).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED', status: 409 });
    const denial = (await s.audits()).find((event) => event.outcome === 'deny');
    expect(denial?.metadata).toMatchObject({ reason: 'LIMIT_EXCEEDED', subject });
    // Revoked sessions do not count, and the refused token was not redeemed.
    await f.iam.api.trust.revokeSessions(f.ownerCredential, {
      tenantId: f.tenantId,
      trustId: s.trust.id,
    });
    f.advance(1);
    expect((await s.exchange(third)).session.trustId).toBe(s.trust.id);
  });

  it('enforces the tenant’s network allowlist on issuance and on every use', async () => {
    const s = await setup();
    const { f } = s;
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'] },
    });
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'ci' }, fn);
    const external = s.token();
    await expect(from('198.51.100.8', () => s.exchange(external))).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
    });
    const credential = await from('203.0.113.5', () => s.exchange(external));
    expect((await f.iam.store.get<Session>('sessions', credential.session.id))!.client).toEqual({
      ip: '203.0.113.5',
      userAgent: 'ci',
    });
    await expect(
      from('198.51.100.8', () => f.iam.authenticate({ token: credential.token })),
    ).rejects.toMatchObject({ code: 'IP_NOT_ALLOWED' });
    expect(
      (await from('203.0.113.9', () => f.iam.authenticate({ token: credential.token }))).session.id,
    ).toBe(credential.session.id);
  });

  it('refetches keys for an unknown kid at most once per cooldown', async () => {
    const first = generateTestKey('RS256', 'k1');
    const second = generateTestKey('RS256', 'k2');
    const jwksUri = 'https://keys.example.test/jwks';
    let served = [first.publicJwk];
    let fetches = 0;
    const s = await setup({
      webIdentity: {
        fetchJson: async (url) => {
          if (url.href !== jwksUri) throw new Error(`unexpected fetch ${url.href}`);
          fetches++;
          return { keys: served };
        },
      },
    });
    const { f } = s;
    await f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: s.provider.id,
      jwks: null,
      jwksUri,
    });
    await s.exchange(s.token({}, {}, first));
    expect(fetches).toBe(1);
    // The IdP rotates; a token with the new kid within the cooldown is refused without another fetch.
    served = [first.publicJwk, second.publicJwk];
    await expect(s.exchange(s.token({}, {}, second))).rejects.toMatchObject({
      code: 'WEB_IDENTITY_REJECTED',
    });
    expect(fetches).toBe(1);
    expect(
      (await s.audits())
        .filter((event) => event.outcome === 'deny')
        .map((event) => event.metadata?.reason),
    ).toEqual(['unknown-key']);
    f.advance(31_000);
    await s.exchange(s.token({}, {}, second));
    expect(fetches).toBe(2);
    // The old key keeps working from the refreshed set.
    await s.exchange(s.token({}, {}, first));
    expect(fetches).toBe(2);
  });

  it('issues against the trust and provider as they stand at issuance, not at verification', async () => {
    const jwksUri = 'https://keys.example.test/jwks';
    const legacyAudience = 'https://legacy.acme.example';
    /** An administrator's change that lands while the exchange is fetching the provider's keys. */
    let during: (() => Promise<unknown>) | undefined;
    const s: Setup = await setup({
      webIdentity: {
        fetchJson: async (url) => {
          if (url.href !== jwksUri) throw new Error(`unexpected fetch ${url.href}`);
          const change = during;
          during = undefined;
          if (change) {
            s.f.advance(1);
            await change();
          }
          return { keys: [s.rsa.publicJwk] };
        },
      },
    });
    const { f } = s;
    const target = { tenantId: f.tenantId, providerId: s.provider.id };
    f.advance(1);
    await f.iam.api.oidcProviders.update(f.ownerCredential, {
      ...target,
      jwks: null,
      jwksUri,
      audiences: [audience, legacyAudience],
    });
    const sessions = async () =>
      (await f.iam.store.find<Session>('sessions', { roleId: s.role.id })).filter(
        (session) => session.trustId === s.trust.id,
      );

    // A change that does not touch what the token was checked against issues as usual.
    during = () => f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, name: 'CI' });
    const issued = await s.exchange(s.token({ aud: legacyAudience }));
    expect(during).toBeUndefined();
    expect((await f.iam.store.get<Session>('sessions', issued.session.id))!.sessionTags).toEqual({
      repo: 'acme/app',
    });

    // The provider drops the token's audience while its keys are being fetched.
    during = () =>
      f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, audiences: [audience] });
    await expect(s.exchange(s.token({ aud: legacyAudience }))).rejects.toMatchObject({
      code: 'WEB_IDENTITY_REJECTED',
    });
    expect(during).toBeUndefined();
    // The audience change also ended the session issued under the old audiences.
    expect(await sessions()).toEqual([]);
    expect(
      (await f.iam.store.get<OidcProvider>('oidcProviders', s.provider.id))!.sessionsRevokedBefore,
    ).toBe(f.now() + 1);

    // The trust's conditions tighten while the keys are being fetched.
    during = () =>
      f.iam.api.trust.update(f.ownerCredential, {
        tenantId: f.tenantId,
        trustId: s.trust.id,
        conditions: { StringEquals: { 'token.sub': subject, 'token.repository_owner': 'other' } },
      });
    await expect(s.exchange(s.token())).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    expect(during).toBeUndefined();

    expect(await sessions()).toEqual([]);
    expect(await f.iam.store.find('webIdentityReplays')).toHaveLength(1);
    expect(
      (await s.audits())
        .filter((event) => event.outcome === 'deny')
        .map((event) => event.metadata?.reason),
    ).toEqual(['provider', 'conditions']);
  });

  it('holds the sts.webIdentity.allowedIssuers pin for providers registered before it narrowed', async () => {
    const s = await setup();
    const { f } = s;
    // The same database, restarted with a pin that no longer lists the provider's issuer.
    const narrowed = betterIam({
      database: f.database,
      secret: 'organization-fixture-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read', 'documents:write'] },
      resolveResource: async (reference) => reference,
      authentication: {
        sessionLifetimeMs: 7 * 86400000,
        sessionIdleTimeoutMs: 7 * 86400000,
        now: f.now,
      },
      sts: { webIdentity: { enabled: true, allowedIssuers: ['https://gitlab.example.test'] } },
    });
    const target = { tenantId: f.tenantId, trustId: s.trust.id };
    await expect(
      narrowed.api.sts.assumeRoleWithWebIdentity({
        ...target,
        webIdentityToken: s.token(),
        sessionName: 'ci-run',
      }),
    ).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    expect(
      await narrowed.api.trust.evaluateWebIdentity(f.ownerCredential, {
        ...target,
        webIdentityToken: s.token(),
      }),
    ).toEqual({ verified: false, reason: 'issuer' });
    expect((await s.audits()).map((event) => [event.outcome, event.metadata?.reason])).toEqual([
      ['deny', 'issuer'],
    ]);
    expect(await f.iam.store.find('sessions', { trustId: s.trust.id })).toEqual([]);
    // The deployment that still admits the issuer keeps accepting its tokens.
    await s.exchange(s.token());
  });

  it('issues session JWTs that carry the web identity', async () => {
    const signing = generateTestKey('EdDSA', 'iam-1');
    const s = await setup({ sts: { jwt: { signingKeys: [signing.privateJwk as never] } } });
    const credential = await s.exchange(s.token(), { format: 'jwt', durationSeconds: 600 });
    expect(credential.format).toBe('jwt');
    const { header, payload } = decodeTestJwt(credential.token);
    expect(header).toMatchObject({ alg: 'EdDSA', kid: 'iam-1', typ: 'biam-session+jwt' });
    expect(payload).toMatchObject({
      sub: s.account.id,
      tid: s.f.tenantId,
      kind: 'role',
      mfa: false,
      role: s.role.id,
      trust: s.trust.id,
      session_name: 'ci-run',
      source_identity: 'octocat',
      idp: s.provider.id,
      idp_sub: subject,
    });
    expect(payload.exp).toBe((payload.iat as number) + 600);
    // Attribution only: no tags, policies, authority ids or hashes.
    expect(Object.keys(payload).sort()).toEqual([
      'aud',
      'auth_time',
      'exp',
      'iat',
      'idp',
      'idp_sub',
      'iss',
      'jti',
      'kind',
      'mfa',
      'nbf',
      'role',
      'session_name',
      'sid',
      'source_identity',
      'sub',
      'tid',
      'trust',
    ]);
    expect(await s.works(credential.token)).toBe(true);
    expect(await s.allowed(credential.token, 'documents:write')).toBe(true);
    await s.f.iam.api.trust.revokeSessions(s.f.ownerCredential, {
      tenantId: s.f.tenantId,
      trustId: s.trust.id,
    });
    expect(await s.works(credential.token)).toBe(false);
  });
});

describe('ending web-identity sessions', () => {
  it('kill switches and revocation end live sessions', async () => {
    const s = await setup();
    const { f } = s;
    const target = { tenantId: f.tenantId, providerId: s.provider.id };

    // Disabling the provider ends its sessions for good: re-enabling it does not bring them back.
    const killed = await s.exchange(s.token());
    const disabled = await f.iam.api.oidcProviders.update(f.ownerCredential, {
      ...target,
      enabled: false,
    });
    expect(disabled.sessionsRevokedBefore).toBe(f.now() + 1);
    expect(await f.iam.store.get('sessions', killed.session.id)).toBeUndefined();
    expect(await s.works(killed.token)).toBe(false);
    await expect(s.exchange(s.token())).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    await f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, enabled: true });
    expect(await s.works(killed.token)).toBe(false);

    // oidcProviders.revokeSessions: watermark plus eager deletion.
    f.advance(1);
    const first = await s.exchange(s.token());
    expect(await s.works(first.token)).toBe(true);
    const revokedByProvider = await f.iam.api.oidcProviders.revokeSessions(
      f.ownerCredential,
      target,
    );
    expect(revokedByProvider).toEqual({
      providerId: s.provider.id,
      sessionsRevokedBefore: f.now() + 1,
      revoked: 1,
    });
    expect(await f.iam.store.get('sessions', first.session.id)).toBeUndefined();
    expect(await s.works(first.token)).toBe(false);
    expect(await s.audits('role:sessions-revoked')).toHaveLength(1);
    expect((await s.audits('role:sessions-revoked'))[0]).toMatchObject({
      resourceId: s.provider.id,
      metadata: { sessionsRevokedBefore: f.now() + 1, revoked: 1 },
    });

    // trust.revokeSessions.
    f.advance(1);
    const second = await s.exchange(s.token());
    expect(await s.works(second.token)).toBe(true);
    expect(
      (
        await f.iam.api.trust.revokeSessions(f.ownerCredential, {
          tenantId: f.tenantId,
          trustId: s.trust.id,
        })
      ).revoked,
    ).toBe(1);
    expect(await s.works(second.token)).toBe(false);

    // Disabling the service account ends its sessions.
    f.advance(1);
    const third = await s.exchange(s.token());
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: s.account.id,
      status: 'disabled',
    });
    expect(await s.works(third.token)).toBe(false);
    await expect(s.exchange(s.token())).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: s.account.id,
      status: 'active',
    });

    // Revoking the trust deletes its sessions and refuses further exchanges.
    const fourth = await s.exchange(s.token());
    await f.iam.api.trust.revoke(f.ownerCredential, { tenantId: f.tenantId, trustId: s.trust.id });
    expect(await f.iam.store.get('sessions', fourth.session.id)).toBeUndefined();
    expect(await s.works(fourth.token)).toBe(false);
    await expect(s.exchange(s.token())).rejects.toMatchObject({ code: 'WEB_IDENTITY_REJECTED' });
  });

  it('refuses the service account’s own API key on the classic AssumeRole path', async () => {
    const s = await setup();
    const { f } = s;
    const assumer = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assumer',
      permissions: ['iam:roles:assume'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: s.account.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: s.account.id,
    });
    await expect(
      f.iam.api.roles.assume({ token: key.token }, { tenantId: f.tenantId, trustId: s.trust.id }),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: 'Role trust does not permit assumption',
    });
  });
});

describe('trust.evaluateWebIdentity', () => {
  it('dry-runs verification, conditions and mappings without redeeming the token', async () => {
    const s = await setup();
    const { f } = s;
    const target = { tenantId: f.tenantId, trustId: s.trust.id };
    const external = s.token();
    const { payload } = decodeTestJwt(external);
    expect(
      await f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, {
        ...target,
        webIdentityToken: external,
      }),
    ).toEqual({
      verified: true,
      claims: {
        iss: issuer,
        sub: subject,
        aud: audience,
        iat: payload.iat,
        exp: payload.exp,
        jti: payload.jti,
      },
      conditions: { matched: true, failed: [] },
      sessionTags: { repo: 'acme/app' },
      sourceIdentity: 'octocat',
    });
    // Not redeemed: the exchange still accepts it.
    expect(await f.iam.store.find('webIdentityReplays')).toEqual([]);
    await s.exchange(external);

    const evaluate = (webIdentityToken: string) =>
      f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, { ...target, webIdentityToken });
    expect(
      await evaluate(
        s.token({ sub: 'repo:acme/other:ref:refs/heads/main', repository_owner: 'x' }),
      ),
    ).toMatchObject({
      verified: true,
      reason: 'conditions',
      conditions: {
        matched: false,
        failed: ['StringEquals:token.sub', 'StringEquals:token.repository_owner'],
      },
    });
    expect(await evaluate(s.token({ actor: undefined }))).toMatchObject({
      verified: true,
      reason: 'source-identity',
      conditions: { matched: true, failed: [] },
    });
    expect(await evaluate(tamperPayload(s.token(), { sub: 'x' }))).toEqual({
      verified: false,
      reason: 'signature',
    });
    expect(await evaluate('garbage')).toEqual({ verified: false, reason: 'malformed' });

    // Web trusts only; authorized before the trust is read.
    const identityTrust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: s.role.id,
      requireMfa: false,
    });
    await expect(
      f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, {
        tenantId: f.tenantId,
        trustId: identityTrust.id,
        webIdentityToken: external,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    for (const trustId of [s.trust.id, randomUUID()])
      await expect(
        f.iam.api.trust.evaluateWebIdentity(alice, {
          tenantId: f.tenantId,
          trustId,
          webIdentityToken: external,
        }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, {
        tenantId: f.tenantId,
        trustId: randomUUID(),
        webIdentityToken: external,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('names the stored state that would refuse the exchange, which the exchange never reveals', async () => {
    const s = await setup();
    const { f } = s;
    const target = { tenantId: f.tenantId, trustId: s.trust.id };
    const evaluate = async (claims: Record<string, unknown> = {}) =>
      f.iam.api.trust.evaluateWebIdentity(f.ownerCredential, {
        ...target,
        webIdentityToken: s.token(claims),
      });
    /** Replaces fields of a stored record; an `undefined` value removes the field. */
    const patch = (collection: string, recordId: string, fields: Record<string, unknown>) =>
      f.iam.store.transaction(async (tx) => {
        const next: Record<string, unknown> = {
          ...(await tx.get(collection, recordId))!,
          ...fields,
        };
        for (const [key, value] of Object.entries(fields))
          if (value === undefined) delete next[key];
        await tx.put(collection, next as never);
      });
    /** The evaluation's reason, and the public exchange's answer to a fresh token. */
    const judged = async (): Promise<[string | undefined, unknown]> => {
      const { reason, verified } = await evaluate();
      expect(verified).toBe(true);
      let exchanged: unknown;
      try {
        exchanged = (await s.exchange(s.token())).session.trustId;
      } catch (error) {
        exchanged = (error as { code?: string }).code;
      }
      return [reason, exchanged];
    };
    expect((await evaluate()).reason).toBeUndefined();

    // A disabled provider.
    const provider = { tenantId: f.tenantId, providerId: s.provider.id };
    await f.iam.api.oidcProviders.update(f.ownerCredential, { ...provider, enabled: false });
    expect(await judged()).toEqual(['provider', 'WEB_IDENTITY_REJECTED']);
    await f.iam.api.oidcProviders.update(f.ownerCredential, { ...provider, enabled: true });

    // An inactive, then an expired, service account; a token problem comes first, as in the exchange.
    const account = { tenantId: f.tenantId, identityId: s.account.id };
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
      ...account,
      status: 'disabled',
    });
    expect(await judged()).toEqual(['service-account', 'WEB_IDENTITY_REJECTED']);
    expect((await evaluate({ repository_owner: 'other' })).reason).toBe('conditions');
    await f.iam.api.serviceAccounts.setStatus(f.ownerCredential, { ...account, status: 'active' });
    await patch('identities', s.account.id, { expiresAt: f.now() - 1 });
    expect(await judged()).toEqual(['service-account', 'WEB_IDENTITY_REJECTED']);
    await patch('identities', s.account.id, { expiresAt: undefined });

    // A missing role.
    const role = (await f.iam.store.get<Role>('roles', s.role.id))!;
    await f.iam.store.transaction((tx) => tx.delete('roles', role.id));
    expect(await judged()).toEqual(['role', 'WEB_IDENTITY_REJECTED']);
    await f.iam.store.transaction((tx) => tx.insert('roles', role));

    // A revoked authority behind the trust, then behind the provider.
    const trust = (await f.iam.store.get<Trust>('trusts', s.trust.id))!;
    await patch('trusts', trust.id, { authorityId: randomUUID() });
    expect(await judged()).toEqual(['authority', 'WEB_IDENTITY_REJECTED']);
    await patch('trusts', trust.id, { authorityId: trust.authorityId });
    await patch('oidcProviders', s.provider.id, { authorityId: randomUUID() });
    expect(await judged()).toEqual(['authority', 'WEB_IDENTITY_REJECTED']);
    await patch('oidcProviders', s.provider.id, { authorityId: s.provider.authorityId });

    // Everything restored, the exchange works again; a revoked trust comes before any token problem.
    expect(await judged()).toEqual([undefined, s.trust.id]);
    await f.iam.api.trust.revoke(f.ownerCredential, target);
    expect(await judged()).toEqual(['trust', 'WEB_IDENTITY_REJECTED']);
    expect((await evaluate({ repository_owner: 'other' })).reason).toBe('trust');
    // The verified claims are still reported alongside the reason.
    expect(await evaluate()).toMatchObject({ verified: true, claims: { sub: subject } });
  });
});

describe('trust management fixes', () => {
  it('trust.revokeSessions pre-reads the trust in the tenant, as roles.assume does', async () => {
    const s = await setup();
    const { f } = s;
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    await expect(
      f.iam.api.trust.revokeSessions(alice, { tenantId: f.tenantId, trustId: s.trust.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Spec F2: a missing trust, or one asked for under another tenant, is NOT_FOUND.
    await expect(
      f.iam.api.trust.revokeSessions(alice, { tenantId: f.tenantId, trustId: randomUUID() }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    for (const trustId of [s.trust.id, randomUUID()])
      await expect(
        f.iam.api.trust.revokeSessions(f.ownerCredential, { tenantId: f.root.tenant.id, trustId }),
      ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Anonymous callers are refused before the trust is read.
    await expect(
      f.iam.api.trust.revokeSessions(
        { token: 'nope' },
        { tenantId: f.tenantId, trustId: s.trust.id },
      ),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      f.iam.api.trust.revokeSessions(f.ownerCredential, {
        tenantId: f.tenantId,
        trustId: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      await f.iam.api.trust.revokeSessions(f.ownerCredential, {
        tenantId: f.tenantId,
        trustId: s.trust.id,
      }),
    ).toMatchObject({ trustId: s.trust.id, revoked: 0 });
  });

  it('trust.update reads a malformed stored allowedTagKeys as no keys', async () => {
    const s = await setup();
    const { f } = s;
    const identityTrust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: s.role.id,
      requireMfa: false,
    });
    await f.iam.store.transaction(async (tx) => {
      const stored = (await tx.get<Trust>('trusts', identityTrust.id))!;
      await tx.put('trusts', { ...stored, allowedTagKeys: { team: true } as never });
    });
    const updated = await f.iam.api.trust.update(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: identityTrust.id,
      description: 'Break-glass',
    });
    expect(updated.description).toBe('Break-glass');
    expect(updated.sessionsRevokedBefore).toBeUndefined();
  });
});
