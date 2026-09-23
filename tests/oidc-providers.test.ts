import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { Session } from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import type {
  GrantAuthority,
  OidcProvider,
  PublicJwk,
  Trust,
} from '../packages/server/src/models.js';
import { generateTestKey } from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * OIDC provider management (`oidcProviders.*`): CRUD with permissions and recent authentication, the feature gate,
 * issuer, key and URL validation, the per-tenant issuer uniqueness, editing only under the creator's grant authority,
 * and the refusal to delete a provider that live trusts still use.
 */

const issuer = 'https://token.actions.example.test';
const audience = 'https://acme.example';
const key = generateTestKey('RS256', 'rsa-1');
const publicKey = key.publicJwk as PublicJwk;
const publicProviderKeys = [
  'algorithms',
  'audiences',
  'authorityId',
  'clockToleranceSeconds',
  'createdAt',
  'createdBy',
  'enabled',
  'id',
  'issuer',
  'jwks',
  'maxTokenLifetimeSeconds',
  'name',
  'replayProtection',
  'tenantId',
  'updatedAt',
];

type WebIdentityOptions = NonNullable<NonNullable<BetterIamOptions['sts']>['webIdentity']>;

function fixture(webIdentity: WebIdentityOptions = {}) {
  return organizationFixture({ sts: { webIdentity: { enabled: true, ...webIdentity } } });
}

function providerInput(f: OrganizationFixture, extra: Record<string, unknown> = {}) {
  return {
    tenantId: f.tenantId,
    name: 'GitHub Actions',
    issuer,
    audiences: [audience],
    jwks: { keys: [publicKey] },
    ...extra,
  };
}

/** A member holding the given IAM permissions through a role, optionally with a delegated grant authority. */
async function administrator(
  f: OrganizationFixture,
  name: string,
  permissions: string[],
  authority = false,
) {
  const identity = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} role`,
    permissions,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  if (authority)
    await f.iam.api.authorities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: identity.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
      },
    });
  return { identity, credential: { token: (await f.signIn(name)).token } };
}

describe('oidcProviders CRUD', () => {
  it('creates, reads, updates and deletes providers under the permissions and recent authentication', async () => {
    const f = await fixture();
    const created = await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f));
    expect(Object.keys(created).sort()).toEqual(publicProviderKeys);
    expect(created).toMatchObject({
      tenantId: f.tenantId,
      name: 'GitHub Actions',
      issuer,
      audiences: [audience],
      algorithms: ['RS256', 'ES256'],
      maxTokenLifetimeSeconds: 3600,
      clockToleranceSeconds: 30,
      replayProtection: 'single-use',
      enabled: true,
      createdBy: f.ownerId,
      createdAt: f.now(),
    });
    // Static keys are stored as an allowlisted public copy.
    expect(created.jwks!.keys[0]).toMatchObject({ kty: 'RSA', kid: 'rsa-1', n: key.publicJwk.n });
    const stored = (await f.iam.store.get<OidcProvider>('oidcProviders', created.id))!;
    expect(stored.uniqueKey).toBe(`issuer:${issuer}`);
    const authority = await f.iam.store.get<GrantAuthority>(
      'grantAuthorities',
      created.authorityId,
    );
    expect(authority?.identityId).toBe(f.ownerId);

    expect(
      await f.iam.api.oidcProviders.get(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
      }),
    ).toEqual(created);
    expect(await f.iam.api.oidcProviders.list(f.ownerCredential, { tenantId: f.tenantId })).toEqual(
      [created],
    );

    f.advance(1000);
    const updated = await f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: created.id,
      name: 'GitHub',
      audiences: [audience, 'sts.amazonaws.com'],
      jwks: null,
      jwksUri: 'https://token.actions.example.test/.well-known/jwks',
      algorithms: ['RS256'],
      maxTokenLifetimeSeconds: 600,
      clockToleranceSeconds: 5,
      replayProtection: 'off',
    });
    expect(updated).toMatchObject({
      name: 'GitHub',
      audiences: [audience, 'sts.amazonaws.com'],
      jwksUri: 'https://token.actions.example.test/.well-known/jwks',
      algorithms: ['RS256'],
      maxTokenLifetimeSeconds: 600,
      clockToleranceSeconds: 5,
      replayProtection: 'off',
      updatedAt: f.now(),
      createdAt: created.createdAt,
    });
    expect(updated.jwks).toBeUndefined();
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
        name: 'GitHub',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: 'The update changes nothing' });
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
        issuer: 'https://other.example.test',
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
        jwks: { keys: [publicKey] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: 'Give jwks or jwksUri, not both' });

    expect(
      await f.iam.api.oidcProviders.delete(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
      }),
    ).toEqual({ deleted: true });
    expect(await f.iam.store.get('oidcProviders', created.id)).toBeUndefined();
    await expect(
      f.iam.api.oidcProviders.get(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: created.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('requires the provider permissions and recent authentication', async () => {
    const f = await fixture();
    const reader = await administrator(f, 'reader', ['iam:oidc-providers:read']);
    const nobody = await administrator(f, 'nobody', ['iam:trust:read']);
    const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f));
    const target = { tenantId: f.tenantId, providerId: provider.id };

    expect(await f.iam.api.oidcProviders.get(reader.credential, target)).toEqual(provider);
    await expect(
      f.iam.api.oidcProviders.list(nobody.credential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.oidcProviders.create(
        reader.credential,
        providerInput(f, { issuer: 'https://gitlab.example.test' }),
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.oidcProviders.update(reader.credential, { ...target, name: 'Renamed' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.iam.api.oidcProviders.delete(reader.credential, target)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.iam.api.oidcProviders.revokeSessions(reader.credential, target),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Past the five-minute window the owner's session may still read, but not change anything.
    f.advance(6 * 60_000);
    expect(await f.iam.api.oidcProviders.get(f.ownerCredential, target)).toMatchObject({
      id: provider.id,
    });
    for (const call of [
      () =>
        f.iam.api.oidcProviders.create(
          f.ownerCredential,
          providerInput(f, { issuer: 'https://gitlab.example.test' }),
        ),
      () => f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, name: 'Renamed' }),
      () => f.iam.api.oidcProviders.delete(f.ownerCredential, target),
      () => f.iam.api.oidcProviders.revokeSessions(f.ownerCredential, target),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = await f.ownerSignIn();
    expect((await f.iam.api.oidcProviders.update(fresh, { ...target, name: 'Renamed' })).name).toBe(
      'Renamed',
    );
  });

  it('is gated by sts.webIdentity.enabled, except reads, disabling, trust revocation and deletion', async () => {
    const f = await organizationFixture();
    await expect(
      f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f)),
    ).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
      status: 403,
      message: 'Web identity federation is not enabled',
    });
    // A provider registered while the feature was on.
    const now = f.now();
    const authority = (
      await f.iam.store.find<GrantAuthority>('grantAuthorities', {
        tenantId: f.tenantId,
      })
    ).find((item) => item.identityId === f.ownerId)!;
    const seeded: OidcProvider = {
      id: randomUUID(),
      tenantId: f.tenantId,
      uniqueKey: `issuer:${issuer}`,
      name: 'GitHub Actions',
      issuer,
      audiences: [audience],
      jwks: { keys: [publicKey] },
      algorithms: ['RS256'],
      maxTokenLifetimeSeconds: 3600,
      clockToleranceSeconds: 30,
      replayProtection: 'single-use',
      enabled: true,
      authorityId: authority.id,
      createdAt: now,
      createdBy: f.ownerId,
      updatedAt: now,
    };
    await f.iam.store.transaction((tx) => tx.insert('oidcProviders', seeded));
    const target = { tenantId: f.tenantId, providerId: seeded.id };
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, name: 'Renamed' }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, enabled: true, name: 'x' }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // A web trust through it, with a live session, also from while the feature was on.
    const trust: Trust = {
      id: randomUUID(),
      tenantId: f.tenantId,
      kind: 'web-identity',
      sourceTenantId: f.tenantId,
      sourceIdentityId: randomUUID(),
      roleId: randomUUID(),
      requireMfa: false,
      revoked: false,
      providerId: seeded.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app:ref:refs/heads/main' } },
      authorityId: authority.id,
      createdAt: now,
      updatedAt: now,
    };
    const session: Session = {
      id: randomUUID(),
      tenantId: f.tenantId,
      identityId: trust.sourceIdentityId,
      originalIdentityId: trust.sourceIdentityId,
      roleId: trust.roleId,
      trustId: trust.id,
      kind: 'role',
      tokenHash: `hash-${randomUUID()}`,
      createdAt: now,
      lastSeenAt: now,
      authenticatedAt: now,
      expiresAt: now + 900_000,
      mfa: false,
      credentialAuthorityId: authority.id,
      webIdentity: { providerId: seeded.id, issuer, subject: 'repo:acme/app' },
    };
    await f.iam.store.transaction(async (tx) => {
      await tx.insert('trusts', trust);
      await tx.insert('sessions', { ...session, uniqueKey: session.tokenHash } as never);
    });
    // The kill switch keeps working, and ends the provider's sessions for good.
    const disabled = await f.iam.api.oidcProviders.update(f.ownerCredential, {
      ...target,
      enabled: false,
    });
    expect(disabled).toMatchObject({ enabled: false, sessionsRevokedBefore: now + 1 });
    expect(await f.iam.store.get('sessions', session.id)).toBeUndefined();
    expect(await f.iam.api.oidcProviders.list(f.ownerCredential, { tenantId: f.tenantId })).toEqual(
      [expect.objectContaining({ id: seeded.id, enabled: false })],
    );
    // Deletion waits for the trust to be revoked, which also works with the feature off.
    await expect(f.iam.api.oidcProviders.delete(f.ownerCredential, target)).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    expect(
      await f.iam.api.trust.revoke(f.ownerCredential, { tenantId: f.tenantId, trustId: trust.id }),
    ).toMatchObject({ id: trust.id, revoked: true });
    expect(await f.iam.api.oidcProviders.delete(f.ownerCredential, target)).toEqual({
      deleted: true,
    });
  });
});

describe('oidcProviders validation', () => {
  it('refuses private keys, unsafe key URLs, bad issuers and IAM’s own issuer', async () => {
    const f = await fixture();
    const selfIssuer = `${f.iam.endpoint.origin}${f.iam.endpoint.basePath}`;
    const invalid: Record<string, unknown>[] = [
      { jwks: { keys: [key.privateJwk] } },
      { jwks: { keys: [{ ...key.publicJwk, d: 'secret' }] } },
      {
        jwks: { keys: [generateTestKey('RS256').publicJwk].map((jwk) => ({ ...jwk, n: 'AQAB' })) },
      },
      { jwks: { keys: [] } },
      { jwks: undefined, jwksUri: 'http://keys.example.test/jwks' },
      { jwks: undefined, jwksUri: 'https://keys.example.test:8443/jwks' },
      { jwks: undefined, jwksUri: 'https://user:pass@keys.example.test/jwks' },
      { jwks: undefined, jwksUri: 'https://10.0.0.1/jwks' },
      { jwksUri: 'https://keys.example.test/jwks' },
      { issuer: 'http://token.actions.example.test' },
      { issuer: 'not a url' },
      { issuer: 'https://token.actions.example.test?tenant=1' },
      { issuer: 'https://token.actions.example.test#fragment' },
      { issuer: `https://${'a'.repeat(510)}.test` },
      { issuer: selfIssuer },
      { issuer: `${selfIssuer}/` },
      { audiences: [] },
      { audiences: ['x'.repeat(257)] },
      { audiences: Array.from({ length: 11 }, (_, index) => `aud-${index}`) },
      { algorithms: ['HS256'] },
      { algorithms: ['none'] },
      { algorithms: [] },
      { maxTokenLifetimeSeconds: 59 },
      { maxTokenLifetimeSeconds: 86401 },
      { clockToleranceSeconds: 121 },
      { clockToleranceSeconds: -1 },
      { replayProtection: 'sometimes' },
      { enabled: 'yes' },
      { name: '' },
    ];
    for (const extra of invalid)
      await expect(
        f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f, extra) as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await f.iam.store.find('oidcProviders', { tenantId: f.tenantId })).toEqual([]);
    // Loopback http issuers only with the development switch.
    const dev = await fixture({ allowInsecureLocalhost: true });
    expect(
      (
        await dev.iam.api.oidcProviders.create(
          dev.ownerCredential,
          providerInput(dev, { issuer: 'http://127.0.0.1:8080/idp' }),
        )
      ).issuer,
    ).toBe('http://127.0.0.1:8080/idp');
  });

  it('enforces sts.webIdentity.allowedIssuers', async () => {
    const f = await fixture({ allowedIssuers: [issuer] });
    await expect(
      f.iam.api.oidcProviders.create(
        f.ownerCredential,
        providerInput(f, { issuer: 'https://gitlab.example.test' }),
      ),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: 'The issuer is not in sts.webIdentity.allowedIssuers',
    });
    expect((await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f))).issuer).toBe(
      issuer,
    );
  });

  it('allows one provider per issuer in a tenant', async () => {
    const f = await fixture();
    await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f));
    await expect(
      f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f, { name: 'Again' })),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
      status: 409,
      message: 'A provider for this issuer already exists',
    });
    // Another issuer is fine, with keys found by discovery (nothing is fetched now).
    const discovered = await f.iam.api.oidcProviders.create(
      f.ownerCredential,
      providerInput(f, { issuer: 'https://gitlab.example.test', jwks: undefined }),
    );
    expect(discovered.jwks).toBeUndefined();
    expect(discovered.jwksUri).toBeUndefined();
  });
});

describe('oidcProviders authority', () => {
  it('lets only the creator’s grant authority (or root) edit a provider', async () => {
    const f = await fixture();
    const permissions = [
      'iam:oidc-providers:create',
      'iam:oidc-providers:read',
      'iam:oidc-providers:update',
      'iam:oidc-providers:delete',
    ];
    const admin = await administrator(f, 'admin', permissions, true);
    const unauthorized = await administrator(f, 'helper', permissions);
    await expect(
      f.iam.api.oidcProviders.create(unauthorized.credential, providerInput(f)),
    ).rejects.toMatchObject({ code: 'GRANT_AUTHORITY_REQUIRED' });

    const mine = await f.iam.api.oidcProviders.create(admin.credential, providerInput(f));
    const owners = await f.iam.api.oidcProviders.create(
      f.ownerCredential,
      providerInput(f, { issuer: 'https://gitlab.example.test' }),
    );
    expect(mine.authorityId).not.toBe(owners.authorityId);

    // Neither can edit or delete the other's provider.
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: mine.id,
        name: 'Taken over',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.oidcProviders.delete(admin.credential, {
        tenantId: f.tenantId,
        providerId: owners.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // A provider without an authority is controlled by a superior authority.
    await f.iam.store.transaction(async (tx) => {
      const stored = (await tx.get<OidcProvider>('oidcProviders', owners.id))!;
      const { authorityId: _dropped, ...rest } = stored;
      await tx.put('oidcProviders', rest as never);
    });
    await expect(
      f.iam.api.oidcProviders.update(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: owners.id,
        name: 'Mine now',
      }),
    ).rejects.toMatchObject({ code: 'PROTECTED_RESOURCE' });

    // The creator and root may.
    expect(
      (
        await f.iam.api.oidcProviders.update(admin.credential, {
          tenantId: f.tenantId,
          providerId: mine.id,
          name: 'Admin’s',
        })
      ).name,
    ).toBe('Admin’s');
    expect(
      (
        await f.iam.api.oidcProviders.update(f.rootCredential, {
          tenantId: f.tenantId,
          providerId: mine.id,
          enabled: false,
        })
      ).enabled,
    ).toBe(false);
  });

  it('ends the provider’s sessions when it is disabled or its keys or claim rules change, not on a rename', async () => {
    const f = await fixture();
    const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f));
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deployer',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'web-identity',
      providerId: provider.id,
      serviceAccountId: account.id,
      roleId: role.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app:ref:refs/heads/main' } },
    });
    /** A live web-identity session through the provider, created now. */
    const session = async () => {
      const tokenHash = `hash-${randomUUID()}`;
      const row: Session = {
        id: randomUUID(),
        tenantId: f.tenantId,
        identityId: account.id,
        originalIdentityId: account.id,
        roleId: role.id,
        trustId: trust.id,
        kind: 'role',
        tokenHash,
        createdAt: f.now(),
        lastSeenAt: f.now(),
        authenticatedAt: f.now(),
        expiresAt: f.now() + 900_000,
        mfa: false,
        credentialAuthorityId: trust.authorityId,
        webIdentity: { providerId: provider.id, issuer, subject: 'repo:acme/app' },
      };
      await f.iam.store.transaction((tx) =>
        tx.insert('sessions', { ...row, uniqueKey: tokenHash } as never),
      );
      return row.id;
    };
    const alive = async (sessionId: string) => !!(await f.iam.store.get('sessions', sessionId));
    const target = { tenantId: f.tenantId, providerId: provider.id };
    const update = (fields: Record<string, unknown>) =>
      f.iam.api.oidcProviders.update(f.ownerCredential, { ...target, ...fields } as never);

    // A rename and the replay switch keep live sessions.
    const kept = await session();
    for (const fields of [{ name: 'GitHub' }, { replayProtection: 'off' }])
      expect((await update(fields)).sessionsRevokedBefore).toBeUndefined();
    expect(await alive(kept)).toBe(true);

    // The kill switch ends them for good: re-enabling the provider moves no watermark and revives nothing.
    f.advance(1000);
    const killed = await session();
    const disabled = await update({ enabled: false });
    expect(disabled.sessionsRevokedBefore).toBe(f.now() + 1);
    expect(await alive(killed)).toBe(false);
    expect(await alive(kept)).toBe(false);
    f.advance(1000);
    const enabled = await update({ enabled: true });
    expect(enabled.sessionsRevokedBefore).toBe(disabled.sessionsRevokedBefore);
    expect(enabled.enabled).toBe(true);
    const later = await session();

    // Each change to what a token is verified against moves the watermark and deletes the older sessions.
    let watermark = disabled.sessionsRevokedBefore!;
    for (const fields of [
      { audiences: [audience, 'sts.amazonaws.com'] },
      { algorithms: ['RS256'] },
      { maxTokenLifetimeSeconds: 600 },
      { clockToleranceSeconds: 5 },
      { jwks: { keys: [generateTestKey('RS256', 'rsa-2').publicJwk] } },
      { jwks: null, jwksUri: 'https://token.actions.example.test/.well-known/jwks' },
      { jwksUri: 'https://keys.example.test/jwks' },
    ]) {
      f.advance(1000);
      const older = await session();
      const updated = await update(fields);
      expect(updated.sessionsRevokedBefore).toBe(f.now() + 1);
      expect(updated.sessionsRevokedBefore).toBeGreaterThan(watermark);
      watermark = updated.sessionsRevokedBefore!;
      expect(await alive(older)).toBe(false);
      expect((await f.iam.store.get<OidcProvider>('oidcProviders', provider.id))!).toMatchObject({
        sessionsRevokedBefore: watermark,
      });
    }
    expect(await alive(later)).toBe(false);
    // The deletion stays within this provider: a session under another provider's trust is untouched.
    const other = await f.iam.api.oidcProviders.create(
      f.ownerCredential,
      providerInput(f, { issuer: 'https://gitlab.example.test' }),
    );
    f.advance(1000);
    const bystander = await session();
    await f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: other.id,
      audiences: ['https://gitlab.acme.example'],
    });
    expect(await alive(bystander)).toBe(true);
  });

  it('refuses to delete a provider while unrevoked trusts use it', async () => {
    const f = await fixture();
    const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(f));
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deployer',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'web-identity',
      providerId: provider.id,
      serviceAccountId: account.id,
      roleId: role.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app:ref:refs/heads/main' } },
    });
    const target = { tenantId: f.tenantId, providerId: provider.id };
    await expect(f.iam.api.oidcProviders.delete(f.ownerCredential, target)).rejects.toMatchObject({
      code: 'CONFLICT',
      status: 409,
      message: 'Revoke the trusts that use this provider first',
    });
    await f.iam.api.trust.revoke(f.ownerCredential, { tenantId: f.tenantId, trustId: trust.id });
    expect((await f.iam.store.get<Trust>('trusts', trust.id))!.revoked).toBe(true);
    expect(await f.iam.api.oidcProviders.delete(f.ownerCredential, target)).toEqual({
      deleted: true,
    });
  });
});
