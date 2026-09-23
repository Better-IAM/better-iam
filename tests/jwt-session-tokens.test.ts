import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  betterIam,
  createSessionTokenVerifier,
  type BetterIamOptions,
  type SessionTokenSigningOptions,
} from '@better-iam/server';
import type { PolicyDocument, Session, StoredRecord } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { decodeTestJwt, generateTestKey, signTestJwt, type TestKey } from './support/jwt-keys.js';

afterEach(closeFixtures);

/**
 * IAM-signed session JWTs end to end: configuration, issuance by roles.assume and sts.getSessionToken, acceptance by
 * IAM (bound to their stored row), offline verification downstream, audiences, lifetime caps and key rotation.
 */
const ORIGIN = 'http://localhost:3000';
const ISSUER = `${ORIGIN}/api/iam`;
const TYP = 'biam-session+jwt';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const seconds = (ms: number) => Math.floor(ms / 1000);
const claimNames = new Set([
  'iss',
  'aud',
  'sub',
  'tid',
  'sid',
  'jti',
  'iat',
  'nbf',
  'exp',
  'auth_time',
  'kind',
  'mfa',
  'role',
  'trust',
  'src_tid',
  'session_name',
  'source_identity',
  'idp',
  'idp_sub',
]);
const readOnly: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
};

function jwtOptions(
  key: TestKey,
  extra: Partial<SessionTokenSigningOptions> = {},
): Partial<BetterIamOptions> {
  return { sts: { jwt: { signingKeys: [key.privateJwk as never], ...extra } } };
}

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

/** Replaces a stored session row (delete and insert, since stores refuse to move a record between tenants). */
function replaceSession(f: OrganizationFixture, record: Session) {
  return f.iam.store.transaction(async (tx) => {
    await tx.delete('sessions', record.id);
    await tx.insert('sessions', record);
  });
}

async function allowed(f: OrganizationFixture, token: string, action = 'documents:read') {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'jwt-document' },
    })
  ).allowed;
}

/** A same-tenant read-only trust from the owner that admits a `team` tag and an optional source identity. */
async function openTrust(f: OrganizationFixture) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'JWT reader',
    permissions: ['documents:read'],
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  await f.iam.store.transaction(async (tx) => {
    const record = await tx.get<StoredRecord>('trusts', trust.id);
    await tx.put('trusts', {
      ...record!,
      allowedTagKeys: ['team'],
      sourceIdentityMode: 'optional',
    });
  });
  return { role, trust };
}

/** Another IAM instance on the fixture's database and clock, with its own `sts.jwt`. */
function instance(f: OrganizationFixture, jwt?: SessionTokenSigningOptions) {
  return betterIam({
    database: f.database,
    secret: 'organization-fixture-secret-with-32-characters',
    baseURL: ORIGIN,
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
    authentication: {
      sessionLifetimeMs: 7 * 86400000,
      sessionIdleTimeoutMs: 7 * 86400000,
      now: f.now,
    },
    ...(jwt ? { sts: { jwt } } : {}),
  });
}

describe('session JWT configuration', () => {
  it('refuses invalid sts.jwt settings when the deployment is built', async () => {
    const eddsa = generateTestKey('EdDSA', 'k1');
    const rsa = generateTestKey('RS256', 'r1');
    for (const jwt of [
      { signingKeys: [] },
      { signingKeys: [eddsa.publicJwk] },
      { signingKeys: [rsa.privateJwk] },
      { signingKeys: [eddsa.privateJwk], activeKeyId: 'missing' },
      { signingKeys: [eddsa.privateJwk], maxLifetimeSeconds: 100 },
      { signingKeys: [eddsa.privateJwk], verificationKeys: [generateTestKey('ES256').privateJwk] },
      { signingKeys: [eddsa.privateJwk, eddsa.privateJwk] },
    ])
      await expect(
        organizationFixture({ sts: { jwt: jwt as unknown as SessionTokenSigningOptions } }),
      ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
  });
});

describe('session JWT issuance', () => {
  it('issues role sessions and session tokens as signed JWTs bound to their rows', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const { role, trust } = await openTrust(f);
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      format: 'jwt',
      sessionName: 'deploy-7',
      sourceIdentity: 'ops@corp',
      tags: { team: 'red' },
      policy: readOnly,
    });
    expect(assumed).toMatchObject({
      tokenType: 'Bearer',
      format: 'jwt',
      audience: [ISSUER],
      expiresIn: 900,
    });
    expect(assumed.token.length).toBeLessThanOrEqual(4096);
    const { header, payload } = decodeTestJwt(assumed.token);
    expect(header).toEqual({ alg: 'EdDSA', kid: 'k1', typ: TYP });
    const row = await rowOf(f, assumed.token);
    expect(row).toMatchObject({
      format: 'jwt',
      audience: [ISSUER],
      tokenHash: sha256(assumed.token),
      uniqueKey: sha256(assumed.token),
    });
    expect(payload).toEqual({
      iss: ISSUER,
      aud: ISSUER,
      sub: f.ownerId,
      tid: f.tenantId,
      sid: row.id,
      jti: row.id,
      iat: seconds(row.createdAt),
      nbf: seconds(row.createdAt),
      exp: seconds(row.expiresAt),
      auth_time: seconds(row.authenticatedAt),
      kind: 'role',
      mfa: row.mfa,
      role: role.id,
      trust: trust.id,
      src_tid: f.tenantId,
      session_name: 'deploy-7',
      source_identity: 'ops@corp',
    });
    // Tags and policies stay on the row: the token never carries them.
    const body = JSON.stringify(payload);
    for (const secret of ['team', 'red', 'statements', 'documents:read'])
      expect(body).not.toContain(secret);

    const token = await f.iam.api.sts.getSessionToken(f.ownerCredential, {
      format: 'jwt',
      sessionName: 'cli',
    });
    const tokenPayload = decodeTestJwt(token.token).payload;
    expect(Object.keys(tokenPayload).every((claim) => claimNames.has(claim))).toBe(true);
    expect(tokenPayload).toMatchObject({
      kind: 'session-token',
      sub: f.ownerId,
      tid: f.tenantId,
      sid: token.session.id,
      session_name: 'cli',
      mfa: false,
    });
    expect(Number(tokenPayload.exp) - Number(tokenPayload.iat)).toBe(3600);
    for (const claim of ['role', 'trust', 'src_tid', 'source_identity'])
      expect(tokenPayload).not.toHaveProperty(claim);
    expect(await rowOf(f, token.token)).toMatchObject({ kind: 'session-token', format: 'jwt' });

    // IAM accepts both, with their own boundaries.
    expect(await allowed(f, assumed.token)).toBe(true);
    expect(await allowed(f, assumed.token, 'documents:write')).toBe(false);
    expect(await allowed(f, token.token, 'documents:write')).toBe(true);
    expect(
      (await f.iam.authenticate({ headers: { authorization: `Bearer ${token.token}` } })).session
        .id,
    ).toBe(token.session.id);
  });

  it('verifies offline with the published keys; IAM refuses a revoked token at once', async () => {
    const key = generateTestKey('ES256', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const verifier = createSessionTokenVerifier({
      issuer: ISSUER,
      audience: ISSUER,
      jwks: f.iam.sessionTokens!.jwks(),
      now: f.now,
    });
    const person = await f.ownerSignIn();
    const issued = await f.iam.api.sts.getSessionToken(person, { format: 'jwt' });
    expect(decodeTestJwt(issued.token).header).toEqual({ alg: 'ES256', kid: 'k1', typ: TYP });
    expect(await verifier.verify(issued.token)).toMatchObject({
      sid: issued.session.id,
      kind: 'session-token',
    });
    expect(
      await verifier.verifyRequest({ headers: { authorization: `bearer ${issued.token}` } }),
    ).toMatchObject({ sid: issued.session.id });
    expect(await f.iam.sessionTokens!.verify(issued.token)).toMatchObject({
      sid: issued.session.id,
    });

    // Signing out the source ends the token inside IAM; an offline verifier still accepts it until exp.
    await f.iam.api.auth.signOut(person);
    await expect(f.iam.authenticate({ token: issued.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Session token revoked',
    });
    await expect(f.iam.api.sts.getCallerIdentity({ token: issued.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect((await verifier.verify(issued.token)).sid).toBe(issued.session.id);
    await expect(f.iam.sessionTokens!.verify(issued.token)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
      reason: 'revoked',
    });
    // At exp the offline verifier refuses it too.
    f.advance(3600_000 + 10_000);
    await expect(verifier.verify(issued.token)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
      reason: 'expired',
    });
  });

  it('allows only listed audiences the credential may obtain tokens for', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(
      jwtOptions(key, { audiences: ['https://api.example', 'https://reports.example'] }),
    );
    const get = (credential: { token: string }, audience?: string[], policy?: PolicyDocument) =>
      f.iam.api.sts.getSessionToken(credential, {
        format: 'jwt',
        ...(audience ? { audience } : {}),
        ...(policy ? { policy } : {}),
      });
    for (const audience of [
      ['https://other.example'],
      [],
      [' bad'],
      ['a1', 'a2', 'a3', 'a4', 'a5', 'a6'],
    ])
      await expect(get(f.ownerCredential, audience)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });

    // A downstream-only token: verified downstream and online for its audience, never accepted by IAM itself.
    const downstream = await get(f.ownerCredential, ['https://api.example']);
    expect(downstream.audience).toEqual(['https://api.example']);
    expect(decodeTestJwt(downstream.token).payload.aud).toBe('https://api.example');
    await expect(f.iam.authenticate({ token: downstream.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Invalid credentials',
    });
    const api = createSessionTokenVerifier({
      issuer: ISSUER,
      audience: 'https://api.example',
      jwks: f.iam.sessionTokens!.jwks(),
      now: f.now,
    });
    expect((await api.verify(downstream.token)).sid).toBe(downstream.session.id);
    expect(
      (await f.iam.sessionTokens!.verify(downstream.token, { audience: 'https://api.example' }))
        .sid,
    ).toBe(downstream.session.id);
    await expect(f.iam.sessionTokens!.verify(downstream.token)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
    });
    // Naming the issuer as well makes it usable in IAM.
    const both = await get(f.ownerCredential, [ISSUER, 'https://api.example']);
    expect(decodeTestJwt(both.token).payload.aud).toEqual([ISSUER, 'https://api.example']);
    expect((await f.iam.authenticate({ token: both.token })).session.id).toBe(both.session.id);

    // Other audiences need iam:assertions:create on iam/{aud}, under the token's own boundaries.
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Minter',
      permissions: ['iam:session-tokens:create'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const login = await f.signIn('alice');
    expect((await get({ token: login.token })).audience).toEqual([ISSUER]);
    await expect(get({ token: login.token }, ['https://api.example'])).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: 'This credential may not obtain tokens for audience https://api.example',
    });
    await f.iam.api.roles.update(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      permissions: ['iam:session-tokens:create', 'iam:assertions:create'],
    });
    expect((await get({ token: login.token }, ['https://api.example'])).audience).toEqual([
      'https://api.example',
    ]);
    await expect(
      get(f.ownerCredential, ['https://reports.example'], readOnly),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('caps the lifetime and needs sts.jwt', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key, { maxLifetimeSeconds: 600 }));
    const { trust } = await openTrust(f);
    expect(
      (await f.iam.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' })).expiresIn,
    ).toBe(600);
    await expect(
      f.iam.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt', durationSeconds: 900 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((await f.iam.api.sts.getSessionToken(f.ownerCredential)).expiresIn).toBe(3600);
    const assume = async (durationSeconds?: number) =>
      f.iam.api.roles.assume(await f.ownerSignIn(), {
        tenantId: f.tenantId,
        trustId: trust.id,
        format: 'jwt',
        ...(durationSeconds ? { durationSeconds } : {}),
      });
    expect((await assume()).expiresIn).toBe(600);
    await expect(assume(900)).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const plain = await organizationFixture();
    expect(plain.iam.sessionTokens).toBeUndefined();
    await expect(
      plain.iam.api.sts.getSessionToken(plain.ownerCredential, { format: 'jwt' }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED', status: 403 });
    const plainTrust = await openTrust(plain);
    await expect(
      plain.iam.api.roles.assume(await plain.ownerSignIn(), {
        tenantId: plain.tenantId,
        trustId: plainTrust.trust.id,
        format: 'jwt',
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
  });
});

describe('session JWT row binding', () => {
  it('refuses a validly signed JWT whose kind, subject or tenant disagrees with its row', async () => {
    const key = generateTestKey('EdDSA', 'k1');
    const f = await organizationFixture(jwtOptions(key));
    const alice = await f.member('alice');
    const issued = await f.iam.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' });
    const row = await rowOf(f, issued.token);
    const refused = async (token: string) => {
      await expect(f.iam.authenticate({ token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
        status: 401,
        message: 'Credential expired or revoked',
      });
      await expect(f.iam.sessionTokens!.verify(token)).rejects.toMatchObject({
        reason: 'revoked',
      });
    };

    // Signed by the deployment, then the row changes under it: the hash still matches, the binding does not.
    for (const change of [
      { kind: 'role' as const },
      { identityId: alice.id },
      { tenantId: f.root.tenant.id },
      { format: undefined },
    ]) {
      await replaceSession(f, { ...row, ...change });
      await refused(issued.token);
    }
    await replaceSession(f, row);
    expect((await f.iam.authenticate({ token: issued.token })).session.id).toBe(row.id);

    // Signed with the deployment's key but naming another kind, subject or tenant for the same row. Each forged token
    // gets its hash written onto the row, so the hash comparison passes and only the one claim comparison can fail.
    const { payload } = decodeTestJwt(issued.token);
    const rebound = (token: string) =>
      replaceSession(f, { ...row, tokenHash: sha256(token), uniqueKey: sha256(token) });
    for (const change of [{ kind: 'role' }, { sub: alice.id }, { tid: f.root.tenant.id }]) {
      const forged = signTestJwt(key, { ...payload, ...change }, { typ: TYP });
      await rebound(forged);
      await refused(forged);
    }
    // The control: a re-signed token that changes only an unbound claim is accepted once the row holds its hash, so
    // the refusals above come from the claim comparisons alone.
    const control = signTestJwt(key, { ...payload, session_name: 'control' }, { typ: TYP });
    await refused(control);
    await rebound(control);
    expect((await f.iam.authenticate({ token: control })).session.id).toBe(row.id);
    // The same claims re-signed are a different token: the row holds the hash of the issued one only.
    await replaceSession(f, row);
    await refused(control);
    await refused(signTestJwt(key, { ...payload, mfa: true }, { typ: TYP }));
    expect((await f.iam.authenticate({ token: issued.token })).session.id).toBe(row.id);
  });
});

describe('session JWT key rotation', () => {
  it('rotates with a retired key kept in verificationKeys, then drops it', async () => {
    const k1 = generateTestKey('EdDSA', 'k1');
    const k2 = generateTestKey('ES256', 'k2');
    const f = await organizationFixture(jwtOptions(k1));
    const first = await f.iam.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' });

    // Step 1: publish the new key alongside the active one, then make it active.
    const staged = instance(f, {
      signingKeys: [k1.privateJwk as never, k2.privateJwk as never],
      activeKeyId: 'k2',
    });
    expect(staged.sessionTokens!.jwks().keys.map((jwk) => jwk.kid)).toEqual(['k1', 'k2']);
    expect((await staged.authenticate({ token: first.token })).session.id).toBe(first.session.id);
    // activeKeyId takes effect at once: the staged deployment already signs with k2, and accepts what it signs.
    const staging = await staged.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' });
    expect(decodeTestJwt(staging.token).header).toEqual({ alg: 'ES256', kid: 'k2', typ: TYP });
    expect((await staged.authenticate({ token: staging.token })).session.id).toBe(
      staging.session.id,
    );

    // Step 2: the old key moves to verificationKeys; it verifies but no longer signs.
    const second = instance(f, {
      signingKeys: [k2.privateJwk as never],
      verificationKeys: [k1.publicJwk as never],
    });
    expect(second.sessionTokens!.jwks().keys.map((jwk) => jwk.kid)).toEqual(['k2', 'k1']);
    expect((await second.authenticate({ token: first.token })).session.id).toBe(first.session.id);
    const next = await second.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' });
    expect(decodeTestJwt(next.token).header).toEqual({ alg: 'ES256', kid: 'k2', typ: TYP });
    const downstream = createSessionTokenVerifier({
      issuer: ISSUER,
      audience: ISSUER,
      jwks: second.sessionTokens!.jwks(),
      now: f.now,
    });
    expect((await downstream.verify(first.token)).sid).toBe(first.session.id);
    expect((await downstream.verify(next.token)).sid).toBe(next.session.id);

    // Step 3: the retired key is removed; its tokens stop working in IAM at once.
    const third = instance(f, { signingKeys: [k2.privateJwk as never] });
    expect(third.sessionTokens!.jwks().keys.map((jwk) => jwk.kid)).toEqual(['k2']);
    await expect(third.authenticate({ token: first.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Invalid credentials',
    });
    await expect(third.sessionTokens!.verify(first.token)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
    });
    expect((await third.authenticate({ token: next.token })).session.id).toBe(next.session.id);
    expect(await third.sessionTokens!.verify(next.token)).toMatchObject({ sid: next.session.id });
  });
});
