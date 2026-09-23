import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { betterIam, SessionTokenError, type BetterIamOptions } from '@better-iam/server';
import { newCredentialToken } from '@better-iam/auth';
import type { Identity, PolicyDocument, Session, StoredRecord, Tenant } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { generateTestKey, signTestJwt, tamperPayload, type TestKey } from './support/jwt-keys.js';

afterEach(async () => {
  vi.restoreAllMocks();
  await closeFixtures();
});

/**
 * Credential resolution in principals.ts: bearer parsing, prefixed and legacy opaque tokens, session tokens, hybrid
 * session JWTs and web-identity role sessions. Rows of the kinds whose issuing APIs ship in later waves are seeded
 * through `iam.store`; tokens come from `newCredentialToken` and JWTs from the test signer.
 */
const ISSUER = 'http://localhost:3000/api/iam';
const all: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
};
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const legacyToken = () => randomBytes(32).toString('base64url');
type Watermarked = StoredRecord & { sessionsRevokedBefore?: number };

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

/** Writes to the store (writes need a transaction). */
function insert<T extends { id: string }>(f: OrganizationFixture, collection: string, record: T) {
  return f.iam.store.transaction((tx) => tx.insert(collection, record as never)) as Promise<T>;
}
function put(f: OrganizationFixture, collection: string, record: object) {
  return f.iam.store.transaction((tx) => tx.put(collection, record as never));
}
function remove(f: OrganizationFixture, collection: string, id: string) {
  return f.iam.store.transaction((tx) => tx.delete(collection, id));
}

/** Stores a session row for `token` (tokenHash = uniqueKey = sha256 of the token). */
async function seed(f: OrganizationFixture, row: Session, token: string): Promise<string> {
  await insert(f, 'sessions', { ...row, tokenHash: sha256(token), uniqueKey: sha256(token) });
  return token;
}

/** Applies `patch` to a stored record. */
async function patch<T extends StoredRecord>(
  f: OrganizationFixture,
  collection: string,
  id: string,
  change: (record: T) => T,
) {
  await f.iam.store.transaction(async (tx) => {
    const record = await tx.get<T>(collection, id);
    if (!record) throw new Error(`No ${collection} record ${id}`);
    await tx.put(collection, change(record));
  });
}

async function unauthenticated(f: OrganizationFixture, token: string, message?: string) {
  await expect(f.iam.authenticate({ token })).rejects.toMatchObject({
    code: 'UNAUTHENTICATED',
    status: 401,
    ...(message ? { message } : {}),
  });
}

/** Spies on every store read so a test can prove a credential was refused before storage was touched. */
function storeReads(f: OrganizationFixture) {
  return [
    vi.spyOn(f.database, 'get'),
    vi.spyOn(f.database, 'find'),
    vi.spyOn(f.database, 'transaction'),
  ];
}

async function allowed(f: OrganizationFixture, token: string, action = 'documents:read') {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'resolution-document' },
    })
  ).allowed;
}

/** A read-only role in Acme and a same-tenant trust (no MFA) from the owner to it, plus an assumed session. */
async function ownerRole(f: OrganizationFixture) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Resolution reader',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
    },
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    trustId: trust.id,
  });
  return { role, trust, token: assumed.token };
}

/** A service account in Acme with one API key. */
async function apiKey(f: OrganizationFixture) {
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'resolver',
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: account.id,
  });
  return { account, token: key.token };
}

/** Seeds a session token minted from `source`, as sts.getSessionToken would store it. */
async function sessionToken(
  f: OrganizationFixture,
  source: Session,
  change: Partial<Session> = {},
): Promise<string> {
  const now = f.now();
  return seed(
    f,
    {
      id: randomUUID(),
      tenantId: source.tenantId,
      identityId: source.identityId,
      kind: 'session-token',
      sourceSessionId: source.id,
      tokenHash: '',
      createdAt: now,
      lastSeenAt: now,
      authenticatedAt: source.authenticatedAt,
      expiresAt: Math.min(source.expiresAt, now + 3600_000),
      mfa: source.mfa,
      ...(source.credentialAuthorityId
        ? { credentialAuthorityId: source.credentialAuthorityId }
        : {}),
      ...change,
    },
    newCredentialToken('sts'),
  );
}

describe('bearer parsing', () => {
  it('accepts the bearer scheme in any case for API keys, role sessions and JWTs', async () => {
    const f = await organizationFixture();
    const { token: key } = await apiKey(f);
    const { token: role } = await ownerRole(f);
    expect(
      (await f.iam.authenticate({ headers: { authorization: `bearer ${key}` } })).session.kind,
    ).toBe('api-key');
    expect(
      (await f.iam.authenticate({ headers: { authorization: `BEARER ${role}` } })).session.kind,
    ).toBe('role');
    // A malformed header still ends in the auth service's refusal.
    await expect(
      f.iam.authenticate({ headers: { authorization: `Bearer  ${key}` } }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
});

describe('prefixed and legacy opaque tokens', () => {
  it('refuses a prefixed token with a bad shape or checksum before any storage read', async () => {
    const f = await organizationFixture();
    const good = newCredentialToken('key');
    const flipped = `${good.slice(0, 20)}${good[20] === 'A' ? 'B' : 'A'}${good.slice(21)}`;
    const reads = storeReads(f);
    for (const bad of [good.slice(0, -1), flipped, `${good}x`, 'biam_zzz_' + good.slice(9)]) {
      await unauthenticated(f, bad, 'Invalid credentials');
      await expect(
        f.iam.authenticate({ headers: { authorization: `Bearer ${bad}` } }),
      ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    }
    for (const spy of reads) expect(spy).not.toHaveBeenCalled();
  });

  it('requires the stored kind to match the prefix, with no fallback to the auth service', async () => {
    const f = await organizationFixture();
    const { token } = await apiKey(f);
    const key = await rowOf(f, token);
    // An API-key row presented with a role prefix.
    const misrouted = await seed(f, { ...key, id: randomUUID() }, newCredentialToken('rol'));
    await unauthenticated(f, misrouted, 'Invalid credentials');
    // A user session presented as an API key.
    const user = await rowOf(f, f.ownerCredential.token);
    const disguised = await seed(f, { ...user, id: randomUUID() }, newCredentialToken('key'));
    await unauthenticated(f, disguised, 'Invalid credentials');
    // An unknown prefixed token.
    await unauthenticated(f, newCredentialToken('sts'), 'Invalid credentials');
    // A prefixed user token goes to the auth service.
    expect((await f.iam.authenticate(f.ownerCredential)).session.kind).toBe('user');
  });

  it('still resolves legacy unprefixed API-key and role rows, and fails closed on unknown kinds', async () => {
    const f = await organizationFixture();
    const { token: keyToken } = await apiKey(f);
    const { token: roleToken } = await ownerRole(f);
    const legacyKey = await seed(
      f,
      { ...(await rowOf(f, keyToken)), id: randomUUID() },
      legacyToken(),
    );
    const legacyRole = await seed(
      f,
      { ...(await rowOf(f, roleToken)), id: randomUUID() },
      legacyToken(),
    );
    expect((await f.iam.authenticate({ token: legacyKey })).session.kind).toBe('api-key');
    expect((await f.iam.authenticate({ token: legacyRole })).session.kind).toBe('role');
    expect(await allowed(f, legacyRole)).toBe(true);
    const unknown = await seed(
      f,
      { ...(await rowOf(f, keyToken)), id: randomUUID(), kind: 'gizmo' as Session['kind'] },
      legacyToken(),
    );
    await unauthenticated(f, unknown, 'Invalid credential kind');
  });
});

describe('role session watermarks', () => {
  it('refuses role sessions created before the role or trust watermark', async () => {
    const f = await organizationFixture();
    const { role, trust, token } = await ownerRole(f);
    const created = (await rowOf(f, token)).createdAt;
    await patch<Watermarked>(f, 'roles', role.id, (record) => ({
      ...record,
      sessionsRevokedBefore: created + 1,
    }));
    await unauthenticated(f, token, 'Role credential revoked');
    f.advance(1000);
    const later = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect((await f.iam.authenticate({ token: later.token })).session.kind).toBe('role');
    await patch<Watermarked>(f, 'trusts', trust.id, (record) => ({
      ...record,
      sessionsRevokedBefore: f.now() + 1,
    }));
    await unauthenticated(f, later.token, 'Role credential revoked');
  });
});

describe('session tokens', () => {
  it('works for a user source and uses the identity grants', async () => {
    const f = await organizationFixture();
    const source = await rowOf(f, f.ownerCredential.token);
    const token = await sessionToken(f, source);
    expect(token).toMatch(/^biam_sts_[A-Za-z0-9_-]{49}$/);
    const principal = await f.iam.authenticate({ headers: { authorization: `bearer ${token}` } });
    expect(principal.session).toMatchObject({ kind: 'session-token', sourceSessionId: source.id });
    expect(await allowed(f, token)).toBe(true);
  });

  it('ends with its source: sign-out, idle-out, key rotation and authority revocation', async () => {
    const f = await organizationFixture();
    const person = await f.ownerSignIn();
    const fromUser = await sessionToken(f, await rowOf(f, person.token));
    expect((await f.iam.authenticate({ token: fromUser })).session.kind).toBe('session-token');
    await f.iam.api.auth.signOut(person);
    await unauthenticated(f, fromUser, 'Session token revoked');

    const idle = await f.ownerSignIn();
    const idleSource = await rowOf(f, idle.token);
    const fromIdle = await sessionToken(f, idleSource);
    await patch<Session>(f, 'sessions', idleSource.id, (record) => ({
      ...record,
      lastSeenAt: f.now() - 7 * 86400000,
    }));
    await unauthenticated(f, fromIdle);

    const { token: keyToken } = await apiKey(f);
    const key = await rowOf(f, keyToken);
    const fromKey = await sessionToken(f, key);
    expect((await f.iam.authenticate({ token: fromKey })).session.credentialAuthorityId).toBe(
      key.credentialAuthorityId,
    );
    await f.iam.api.credentials.rotate(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      credentialId: key.id,
    });
    await unauthenticated(f, fromKey, 'Session token revoked');

    const { token: otherKey } = await apiKey(f);
    const other = await rowOf(f, otherKey);
    const fromOther = await sessionToken(f, other);
    expect((await f.iam.authenticate({ token: fromOther })).session.kind).toBe('session-token');
    await patch<StoredRecord & { revoked: boolean }>(
      f,
      'grantAuthorities',
      other.credentialAuthorityId!,
      (record) => ({ ...record, revoked: true }),
    );
    await unauthenticated(f, fromOther);
  });

  it('refuses tokens that outlive their source, change authority, or come from impersonation or a role', async () => {
    const f = await organizationFixture();
    const source = await rowOf(f, f.ownerCredential.token);
    await unauthenticated(
      f,
      await sessionToken(f, source, { expiresAt: source.expiresAt + 1000 }),
      'Session token revoked',
    );
    const { token: keyToken } = await apiKey(f);
    const key = await rowOf(f, keyToken);
    await unauthenticated(
      f,
      await sessionToken(f, key, { credentialAuthorityId: randomUUID() }),
      'Session token revoked',
    );
    const { token: roleToken } = await ownerRole(f);
    await unauthenticated(
      f,
      await sessionToken(f, await rowOf(f, roleToken)),
      'Session token revoked',
    );
    const impersonated = await f.ownerSignIn();
    const impersonatedRow = await rowOf(f, impersonated.token);
    const fromImpersonation = await sessionToken(f, impersonatedRow);
    await patch<Session>(f, 'sessions', impersonatedRow.id, (record) => ({
      ...record,
      impersonatorId: f.ownerId,
    }));
    await unauthenticated(f, fromImpersonation, 'Session token revoked');
    // The unchanged token still works.
    expect((await f.iam.authenticate({ token: await sessionToken(f, source) })).session.kind).toBe(
      'session-token',
    );
  });

  it("judges the recorded address against the tenant's allowlist", async () => {
    const f = await organizationFixture();
    const source = await rowOf(f, f.ownerCredential.token);
    const token = await sessionToken(f, source, { client: { ip: '203.0.113.9' } });
    expect((await f.iam.authenticate({ token })).session.kind).toBe('session-token');
    await patch<Tenant>(f, 'tenants', f.tenantId, (tenant) => ({
      ...tenant,
      authPolicy: { ...tenant.authPolicy, allowedIpRanges: ['10.0.0.0/8'] },
    }));
    await expect(f.iam.authenticate({ token })).rejects.toMatchObject({ code: 'IP_NOT_ALLOWED' });
  });
});

describe('session JWTs', () => {
  function jwtOptions(key: TestKey): Partial<BetterIamOptions> {
    return { sts: { jwt: { signingKeys: [key.privateJwk as never] } } };
  }

  /** Claims binding a JWT to a stored row. */
  function claimsFor(row: Session, change: Record<string, unknown> = {}) {
    const seconds = (ms: number) => Math.floor(ms / 1000);
    return {
      iss: ISSUER,
      aud: ISSUER,
      sub: row.identityId,
      tid: row.tenantId,
      sid: row.id,
      jti: row.id,
      iat: seconds(row.createdAt),
      nbf: seconds(row.createdAt),
      exp: seconds(row.expiresAt),
      auth_time: seconds(row.authenticatedAt),
      kind: row.kind,
      mfa: row.mfa,
      ...(row.roleId ? { role: row.roleId } : {}),
      ...(row.trustId ? { trust: row.trustId } : {}),
      ...change,
    };
  }

  /** A JWT-format copy of a real role session, signed with `key`. */
  async function jwtRoleSession(f: OrganizationFixture, key: TestKey) {
    const { token } = await ownerRole(f);
    const row: Session = {
      ...(await rowOf(f, token)),
      id: randomUUID(),
      format: 'jwt',
      audience: [ISSUER],
    };
    const jwt = signTestJwt(key, claimsFor(row), { typ: 'biam-session+jwt' });
    await seed(f, row, jwt);
    return { jwt, row };
  }

  it('accepts a row-backed JWT as a token and as a bearer in any case', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { jwt, row } = await jwtRoleSession(f, key);
    expect((await f.iam.authenticate({ token: jwt })).session.id).toBe(row.id);
    for (const scheme of ['Bearer', 'bearer'])
      expect(
        (await f.iam.authenticate({ headers: { authorization: `${scheme} ${jwt}` } })).session.id,
      ).toBe(row.id);
    expect(await allowed(f, jwt)).toBe(true);
    expect(await allowed(f, jwt, 'documents:write')).toBe(false);
  });

  it('refuses a tampered token without reading storage', async () => {
    const key = generateTestKey('ES256', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { jwt, row } = await jwtRoleSession(f, key);
    const reads = storeReads(f);
    for (const bad of [
      tamperPayload(jwt, { sub: 'usr_someone_else' }),
      tamperPayload(jwt, { exp: Math.floor(row.expiresAt / 1000) + 60 }),
      signTestJwt(generateTestKey('EdDSA', 'k1'), claimsFor(row), { typ: 'biam-session+jwt' }),
      signTestJwt(key, claimsFor(row), { typ: 'JWT' }),
      signTestJwt(key, claimsFor(row), { typ: 'biam-session+jwt', alg: 'ES384' }),
      signTestJwt(key, claimsFor(row), { typ: 'biam-session+jwt', kid: 'unknown' }),
      signTestJwt({ alg: 'HS256', secret: key.publicJwk.x as string }, claimsFor(row), {
        typ: 'biam-session+jwt',
        kid: 'k1',
      }),
      signTestJwt(key, claimsFor(row, { aud: 'https://downstream.example' }), {
        typ: 'biam-session+jwt',
      }),
      signTestJwt(key, claimsFor(row, { kind: 'user' }), { typ: 'biam-session+jwt' }),
    ])
      await unauthenticated(f, bad, 'Invalid credentials');
    // An unsigned token (empty signature segment) is not even JWT-shaped; it is refused unread as well.
    await unauthenticated(
      f,
      signTestJwt({ alg: 'none' }, claimsFor(row), { typ: 'biam-session+jwt', kid: 'k1' }),
    );
    for (const spy of reads) expect(spy).not.toHaveBeenCalled();
  });

  it('requires the stored row to hold exactly this token and match its claims', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { jwt, row } = await jwtRoleSession(f, key);
    // Validly signed for the same sid, but not the token the row was issued with.
    const other = signTestJwt(key, claimsFor(row, { mfa: !row.mfa }), { typ: 'biam-session+jwt' });
    expect(other).not.toBe(jwt);
    await unauthenticated(f, other, 'Credential expired or revoked');
    // Validly signed for a row that is not a JWT row, or of another identity.
    const { token: opaque } = await ownerRole(f);
    const opaqueRow = await rowOf(f, opaque);
    await unauthenticated(
      f,
      signTestJwt(key, claimsFor(opaqueRow), { typ: 'biam-session+jwt' }),
      'Credential expired or revoked',
    );
    // An audience list naming the issuer is accepted; one without it is not.
    const both: Session = { ...row, id: randomUUID(), audience: [ISSUER, 'https://api.example'] };
    const multi = signTestJwt(key, claimsFor(both, { aud: [ISSUER, 'https://api.example'] }), {
      typ: 'biam-session+jwt',
    });
    await seed(f, both, multi);
    expect((await f.iam.authenticate({ token: multi })).session.id).toBe(both.id);
    const downstream: Session = { ...row, id: randomUUID(), audience: ['https://api.example'] };
    const onlyDownstream = signTestJwt(key, claimsFor(downstream, { aud: 'https://api.example' }), {
      typ: 'biam-session+jwt',
    });
    await seed(f, downstream, onlyDownstream);
    await unauthenticated(f, onlyDownstream, 'Invalid credentials');
    // Deleting the row revokes the token at once.
    await remove(f, 'sessions', row.id);
    await unauthenticated(f, jwt, 'Credential expired or revoked');
  });

  it('is refused by a deployment without sts.jwt and after its key is removed', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { jwt } = await jwtRoleSession(f, key);
    const instance = (sts?: BetterIamOptions['sts']) =>
      betterIam({
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
        ...(sts ? { sts } : {}),
      });
    await expect(instance().authenticate({ token: jwt })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Invalid credentials',
    });
    const rotated = instance({
      jwt: { signingKeys: [generateTestKey('EdDSA', 'k2').privateJwk as never] },
    });
    await expect(rotated.authenticate({ token: jwt })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Invalid credentials',
    });
    // A retired key kept in verificationKeys still verifies.
    const retiring = instance({
      jwt: {
        signingKeys: [generateTestKey('EdDSA', 'k2').privateJwk as never],
        verificationKeys: [key.publicJwk as never],
      },
    });
    expect((await retiring.authenticate({ token: jwt })).session.format).toBe('jwt');
  });

  it('verifies in process with revocation awareness (iam.sessionTokens.verify)', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { jwt, row } = await jwtRoleSession(f, key);
    expect(f.iam.sessionTokens?.issuer).toBe(ISSUER);
    expect(f.iam.sessionTokens?.jwks().keys.map((jwk) => jwk.kid)).toEqual(['k1']);
    expect(await f.iam.sessionTokens!.verify(jwt)).toMatchObject({ sid: row.id, kind: 'role' });
    await expect(f.iam.sessionTokens!.verify(tamperPayload(jwt, { mfa: true }))).rejects.toThrow(
      SessionTokenError,
    );
    await remove(f, 'sessions', row.id);
    await expect(f.iam.sessionTokens!.verify(jwt)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
      reason: 'revoked',
    });
    const plain = await organizationFixture();
    expect(plain.iam.sessionTokens).toBeUndefined();
  });
});

describe('web-identity role sessions', () => {
  async function webFixture() {
    const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'CI reader',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const [ownerAuthority] = await f.iam.store.find<StoredRecord>('grantAuthorities', {
      tenantId: f.tenantId,
      identityId: f.ownerId,
    });
    const now = f.now();
    const authority = () => ({
      id: randomUUID(),
      tenantId: f.tenantId,
      identityId: f.ownerId,
      ceiling: all,
      parentAuthorityId: ownerAuthority!.id,
      revoked: false,
    });
    const trustAuthority = await insert(f, 'grantAuthorities', authority());
    const providerAuthority = await insert(f, 'grantAuthorities', authority());
    const issuer = 'https://token.actions.githubusercontent.com';
    const provider = await insert(f, 'oidcProviders', {
      id: randomUUID(),
      tenantId: f.tenantId,
      uniqueKey: `issuer:${issuer}`,
      name: 'GitHub Actions',
      issuer,
      audiences: ['https://github.com/acme'],
      algorithms: ['RS256'],
      maxTokenLifetimeSeconds: 3600,
      clockToleranceSeconds: 30,
      replayProtection: 'single-use',
      enabled: true,
      authorityId: providerAuthority.id,
      createdAt: now,
      createdBy: f.ownerId,
      updatedAt: now,
    });
    const trust = await insert(f, 'trusts', {
      id: randomUUID(),
      tenantId: f.tenantId,
      kind: 'web-identity',
      sourceTenantId: f.tenantId,
      sourceIdentityId: account.id,
      roleId: role.id,
      requireMfa: false,
      revoked: false,
      providerId: provider.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app:ref:refs/heads/main' } },
      passSourceAttributes: true,
      authorityId: trustAuthority.id,
      createdAt: now,
      createdBy: f.ownerId,
      updatedAt: now,
    });
    const session = (change: Partial<Session> = {}) =>
      seed(
        f,
        {
          id: randomUUID(),
          tenantId: f.tenantId,
          identityId: account.id,
          originalIdentityId: account.id,
          kind: 'role',
          roleId: role.id,
          trustId: trust.id,
          webIdentity: {
            providerId: provider.id,
            issuer,
            subject: 'repo:acme/app:ref:refs/heads/main',
          },
          sessionName: 'ci-run-1',
          credentialAuthorityId: trustAuthority.id,
          tokenHash: '',
          mfa: false,
          createdAt: f.now(),
          lastSeenAt: f.now(),
          authenticatedAt: f.now(),
          expiresAt: f.now() + 900_000,
          ...change,
        },
        newCredentialToken('rol'),
      );
    return { f, account, role, provider, trust, trustAuthority, providerAuthority, session };
  }

  it('resolves a seeded web session and ends it with each kill switch', async () => {
    const web = await webFixture();
    const { f } = web;
    const token = await web.session();
    const principal = await f.iam.authenticate({ token });
    expect(principal.session.webIdentity?.providerId).toBe(web.provider.id);
    expect(principal.identity.id).toBe(web.account.id);

    /** Applies a change, expects the session to be refused, then restores the record and expects it to work. */
    const killSwitch = async (collection: string, id: string, change: object) => {
      const original = await f.iam.store.get(collection, id);
      await put(f, collection, { ...original!, ...change });
      await unauthenticated(f, token);
      await put(f, collection, original!);
      expect((await f.iam.authenticate({ token })).session.id).toBe(principal.session.id);
    };
    await killSwitch('oidcProviders', web.provider.id, { enabled: false });
    await killSwitch('oidcProviders', web.provider.id, { sessionsRevokedBefore: f.now() + 1 });
    await killSwitch('oidcProviders', web.provider.id, { issuer: 'https://other.example' });
    await killSwitch('trusts', web.trust.id, { revoked: true });
    await killSwitch('trusts', web.trust.id, { sessionsRevokedBefore: f.now() + 1 });
    await killSwitch('roles', web.role.id, { sessionsRevokedBefore: f.now() + 1 });
    await killSwitch('grantAuthorities', web.trustAuthority.id, { revoked: true });
    await killSwitch('grantAuthorities', web.providerAuthority.id, { revoked: true });
    await killSwitch('identities', web.account.id, {
      status: 'disabled',
    } satisfies Partial<Identity>);
  });

  it('refuses rows that do not match their trust or provider', async () => {
    const web = await webFixture();
    const { f } = web;
    const owner = await rowOf(f, f.ownerCredential.token);
    // A classic-shaped row (no webIdentity) on a web-identity trust, sourced from the trust's own service account's
    // API key. Every other classic check passes (the source is a live API key of the anchoring identity and tenant),
    // so only the trust-kind guard refuses it: a web trust's service-account key cannot bypass its claim conditions.
    const accountKey = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: web.account.id,
    });
    const keyRow = await rowOf(f, accountKey.token);
    await unauthenticated(
      f,
      await web.session({
        webIdentity: undefined,
        sourceSessionId: keyRow.id,
        sourceTenantId: f.tenantId,
        credentialAuthorityId: keyRow.credentialAuthorityId,
      }),
      'Role credential revoked',
    );
    // A web row anchored to a user: the trust names the owner as its anchor, and everything else matches.
    const userTrust = await insert(f, 'trusts', {
      ...web.trust,
      id: randomUUID(),
      sourceIdentityId: f.ownerId,
    });
    await unauthenticated(
      f,
      await web.session({
        identityId: f.ownerId,
        originalIdentityId: f.ownerId,
        trustId: userTrust.id,
      }),
      'Role credential revoked',
    );
    await unauthenticated(
      f,
      await web.session({ sourceSessionId: owner.id }),
      'Role credential revoked',
    );
    await unauthenticated(
      f,
      await web.session({ credentialAuthorityId: web.providerAuthority.id }),
      'Role credential revoked',
    );
    await unauthenticated(
      f,
      await web.session({
        webIdentity: {
          providerId: randomUUID(),
          issuer: web.provider.issuer as string,
          subject: 'x',
        },
      }),
      'Role credential revoked',
    );
  });

  it('refuses web sessions while federation is disabled', async () => {
    const web = await webFixture();
    const token = await web.session();
    const disabled = betterIam({
      database: web.f.database,
      secret: 'organization-fixture-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read', 'documents:write'] },
      authentication: {
        sessionLifetimeMs: 7 * 86400000,
        sessionIdleTimeoutMs: 7 * 86400000,
        now: web.f.now,
      },
    });
    await expect(disabled.authenticate({ token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Role credential revoked',
    });
  });
});
