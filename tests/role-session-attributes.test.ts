import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, PolicyDocument, Session } from '@better-iam/core';
import { parseCredentialToken } from '@better-iam/auth';
import type { BetterIamOptions } from '@better-iam/server';
import type { Trust } from '../packages/server/src/models.js';
import { createSessionTokenVerifier } from '../packages/server/src/session-tokens.js';
import { decodeTestJwt, generateTestKey } from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * AssumeRole parity (session names, source identities, session tags, per-trust durations, JWT format), the
 * 'role:assumed' audit event, and prefixed API keys. Trust fields that `trust.create`/`trust.update` do not accept yet
 * are patched through `iam.store`.
 */

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const readDocuments: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
};

/** Replaces fields of a stored trust, as records written by later trust APIs would carry them. */
async function patchTrust(
  f: OrganizationFixture,
  trustId: string,
  patch: Partial<Trust> & Record<string, unknown>,
) {
  await f.iam.store.transaction(async (tx) => {
    const current = (await tx.get<Trust>('trusts', trustId))!;
    const next: Record<string, unknown> = { ...current, ...patch };
    for (const [key, value] of Object.entries(patch)) if (value === undefined) delete next[key];
    await tx.put('trusts', next as Trust);
  });
}

/** A reader role in Acme and a same-tenant trust (no MFA) from the owner to it, optionally patched. */
async function ownerTrust(
  f: OrganizationFixture,
  patch: Partial<Trust> & Record<string, unknown> = {},
  document: PolicyDocument = readDocuments,
) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Reader ${Math.random().toString(36).slice(2, 8)}`,
    document,
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  if (Object.keys(patch).length) await patchTrust(f, trust.id, patch);
  return { role, trust };
}

async function sessionRow(f: OrganizationFixture, sessionId: string): Promise<Session> {
  return (await f.iam.store.get<Session>('sessions', sessionId))!;
}

describe('roles.assume session attributes', () => {
  it('returns a RoleCredential with a biam_rol_ token and a 15 minute default', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(Object.keys(assumed).sort()).toEqual([
      'expiresAt',
      'expiresIn',
      'format',
      'session',
      'token',
      'tokenType',
    ]);
    expect(assumed).toMatchObject({
      tokenType: 'Bearer',
      format: 'opaque',
      expiresAt: f.now() + 900_000,
      expiresIn: 900,
    });
    expect(assumed.token).toMatch(/^biam_rol_[A-Za-z0-9_-]{49}$/);
    expect(parseCredentialToken(assumed.token)).toEqual({ type: 'rol' });
    expect(assumed.session).toEqual({
      id: assumed.session.id,
      tenantId: f.tenantId,
      kind: 'role',
      identityId: f.ownerId,
      expiresAt: f.now() + 900_000,
      mfa: false,
      roleId: role.id,
      trustId: trust.id,
    });
    const row = await sessionRow(f, assumed.session.id);
    expect(row.tokenHash).toBe(sha256(assumed.token));
    expect(row.uniqueKey).toBe(row.tokenHash);
    expect(row).not.toHaveProperty('format');
    // The typed token still authenticates as the role session.
    expect((await f.iam.authenticate({ token: assumed.token })).session.kind).toBe('role');
  });

  it('validates and stores the session name, source identity and tags', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f, {
      allowedTagKeys: ['team', 'env'],
      sourceIdentityMode: 'optional',
    });
    const owner = await f.ownerSignIn();
    const base = { tenantId: f.tenantId, trustId: trust.id };
    const invalid = [
      { sessionName: 'x' },
      { sessionName: 'has space' },
      { sessionName: 'a'.repeat(65) },
      { sessionName: 42 },
      { sourceIdentity: 'bad/slash' },
      { sourceIdentity: '' },
      { tags: { 'bad-key': 'x' } },
      { tags: { '1team': 'x' } },
      { tags: { team: 'a', Team: 'b' } },
      { tags: { team: 'x'.repeat(257) } },
      { tags: { team: '<script>' } },
      { tags: { team: 7 } },
      { tags: ['team'] },
      { tags: Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`k${i}`, 'v'])) },
      // 20 tags of 120 characters pack into more than 2048 bytes.
      {
        tags: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`k${i}`, 'v'.repeat(120)])),
      },
    ];
    for (const extra of invalid)
      await expect(
        f.iam.api.roles.assume(owner, { ...base, ...(extra as object) }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const assumed = await f.iam.api.roles.assume(owner, {
      ...base,
      sessionName: 'deploy-42@ci.example',
      sourceIdentity: 'alice@example.test',
      tags: { team: 'Platform Engineering', env: 'prod:eu-west/1' },
    });
    expect(assumed.session).toMatchObject({
      sessionName: 'deploy-42@ci.example',
      sourceIdentity: 'alice@example.test',
    });
    const row = await sessionRow(f, assumed.session.id);
    expect(row).toMatchObject({
      sessionName: 'deploy-42@ci.example',
      sourceIdentity: 'alice@example.test',
      sessionTags: { team: 'Platform Engineering', env: 'prod:eu-west/1' },
    });
    // Tags never appear in the credential itself.
    expect(JSON.stringify(assumed)).not.toContain('Platform Engineering');
  });

  it('applies the trust sourceIdentityMode (forbidden by default)', async () => {
    const f = await organizationFixture();
    const owner = await f.ownerSignIn();
    const cases: [Trust['sourceIdentityMode'], string | undefined, boolean][] = [
      [undefined, undefined, true],
      [undefined, 'alice', false],
      ['forbidden', 'alice', false],
      ['optional', undefined, true],
      ['optional', 'alice', true],
      ['required', undefined, false],
      ['required', 'alice', true],
    ];
    for (const [mode, sourceIdentity, allowed] of cases) {
      const { trust } = await ownerTrust(f, mode ? { sourceIdentityMode: mode } : {});
      const attempt = f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: trust.id,
        ...(sourceIdentity ? { sourceIdentity } : {}),
      });
      if (allowed) {
        const assumed = await attempt;
        expect((await sessionRow(f, assumed.session.id)).sourceIdentity).toBe(sourceIdentity);
      } else
        await expect(attempt).rejects.toMatchObject({
          code: 'ACCESS_DENIED',
          message: 'Role trust does not permit assumption',
        });
    }
  });

  it("admits only the trust's allowedTagKeys, or any key with ['*']", async () => {
    const f = await organizationFixture();
    const owner = await f.ownerSignIn();
    const legacy = await ownerTrust(f);
    const listed = await ownerTrust(f, { allowedTagKeys: ['team'] });
    const any = await ownerTrust(f, { allowedTagKeys: ['*'] });
    const assume = (trustId: string, tags: Record<string, string>) =>
      f.iam.api.roles.assume(owner, { tenantId: f.tenantId, trustId, tags });
    // Legacy trusts admit no tags, but an empty set is no tag at all.
    await expect(assume(legacy.trust.id, { team: 'a' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const untagged = await assume(legacy.trust.id, {});
    expect(await sessionRow(f, untagged.session.id)).not.toHaveProperty('sessionTags');
    await expect(assume(listed.trust.id, { env: 'prod' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Tag keys are matched case-sensitively against the allowlist.
    await expect(assume(listed.trust.id, { Team: 'a' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const tagged = await assume(listed.trust.id, { team: 'a' });
    expect((await sessionRow(f, tagged.session.id)).sessionTags).toEqual({ team: 'a' });
    const wildcard = await assume(any.trust.id, { env: 'prod', Team: 'a' });
    expect((await sessionRow(f, wildcard.session.id)).sessionTags).toEqual({
      env: 'prod',
      Team: 'a',
    });
  });

  it('bounds the duration by the trust, the deployment and the source credential', async () => {
    const f = await organizationFixture();
    const owner = await f.ownerSignIn();
    const assume = (trustId: string, durationSeconds?: number) =>
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId,
        ...(durationSeconds !== undefined ? { durationSeconds } : {}),
      });
    // Legacy trusts: 60..3600, default 900.
    const legacy = await ownerTrust(f);
    for (const seconds of [59, 3601, 1.5])
      await expect(assume(legacy.trust.id, seconds)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    expect((await assume(legacy.trust.id, 3600)).expiresAt).toBe(f.now() + 3_600_000);
    // A trust maximum below the default lowers the default too.
    const short = await ownerTrust(f, { maxSessionSeconds: 600 });
    expect((await assume(short.trust.id)).expiresAt).toBe(f.now() + 600_000);
    await expect(assume(short.trust.id, 601)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A trust maximum above the deployment ceiling (3600 by default) is capped by it.
    const long = await ownerTrust(f, { maxSessionSeconds: 7200 });
    await expect(assume(long.trust.id, 3601)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((await assume(long.trust.id)).expiresAt).toBe(f.now() + 900_000);
  });

  it('allows longer sessions when the deployment ceiling and the trust both allow them', async () => {
    const f = await organizationFixture({ sts: { maxRoleSessionSeconds: 7200 } });
    const owner = await f.ownerSignIn();
    const long = await ownerTrust(f, { maxSessionSeconds: 7200 });
    const legacy = await ownerTrust(f);
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: long.trust.id,
      durationSeconds: 7200,
    });
    expect(assumed.expiresAt).toBe(f.now() + 7_200_000);
    expect(assumed.expiresIn).toBe(7200);
    await expect(
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: long.trust.id,
        durationSeconds: 7201,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Without its own maximum a trust stays at 3600 seconds.
    await expect(
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: legacy.trust.id,
        durationSeconds: 3601,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('never outlives an API key source', async () => {
    const f = await organizationFixture();
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'deployer',
    });
    const own = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assumer',
      permissions: ['iam:roles:assume'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: own.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    const reader = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      document: readDocuments,
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: account.id,
      roleId: reader.id,
      requireMfa: false,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
      expiresInSeconds: 120,
    });
    const assumed = await f.iam.api.roles.assume(
      { token: key.token },
      { tenantId: f.tenantId, trustId: trust.id, durationSeconds: 900 },
    );
    expect(assumed.expiresAt).toBe(key.expiresAt);
    expect(assumed.expiresIn).toBe(120);
    const row = await sessionRow(f, assumed.session.id);
    expect(row).toMatchObject({ mfa: false, authenticatedAt: f.now() });
    expect(row).not.toHaveProperty('mfaAuthenticatedAt');
  });

  it('copies mfa and the MFA time from the source, never its sign-in method', async () => {
    const f = await organizationFixture();
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Operator',
      document: readDocuments,
    });
    // Root's session passed a first-hand TOTP ceremony; the trust keeps its default requireMfa.
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.root.tenant.id,
      sourceIdentityId: f.root.identity.id,
      roleId: role.id,
    });
    const source = (await f.iam.authenticate(f.rootCredential)).session;
    expect(source.mfa).toBe(true);
    expect(typeof source.mfaAuthenticatedAt).toBe('number');
    f.advance(60_000);
    const assumed = await f.iam.api.roles.assume(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(assumed.session.mfa).toBe(true);
    const row = await sessionRow(f, assumed.session.id);
    expect(row).toMatchObject({
      mfa: true,
      mfaAuthenticatedAt: source.mfaAuthenticatedAt,
      authenticatedAt: source.authenticatedAt,
      sourceSessionId: source.id,
      sourceTenantId: f.root.tenant.id,
    });
    expect(row).not.toHaveProperty('method');
    expect(row).not.toHaveProperty('trustedDeviceId');
    // A password-only owner session carries no method or MFA time into its role session either.
    const { trust: ownerOnly } = await ownerTrust(f);
    const plain = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: ownerOnly.id,
    });
    const plainRow = await sessionRow(f, plain.session.id);
    expect(plainRow).not.toHaveProperty('method');
    expect(plainRow).not.toHaveProperty('mfaAuthenticatedAt');
  });

  it('records the issuing client under auth.withClient', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    const assumed = await f.iam.auth.withClient(
      { ip: '203.0.113.7', userAgent: 'deploy-cli/1.0' },
      () => f.iam.api.roles.assume(owner, { tenantId: f.tenantId, trustId: trust.id }),
    );
    expect((await sessionRow(f, assumed.session.id)).client).toEqual({
      ip: '203.0.113.7',
      userAgent: 'deploy-cli/1.0',
    });
    const bare = await f.iam.api.roles.assume(owner, { tenantId: f.tenantId, trustId: trust.id });
    expect(await sessionRow(f, bare.session.id)).not.toHaveProperty('client');
  });

  it('refuses role sources, web-identity trusts and a wrong external ID', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    await expect(
      f.iam.api.roles.assume({ token: assumed.token }, { tenantId: f.tenantId, trustId: trust.id }),
    ).rejects.toMatchObject({ code: 'ROLE_CHAINING_DISABLED' });
    // A web-identity trust is exchanged through sts.assumeRoleWithWebIdentity only, never through roles.assume.
    const { trust: web } = await ownerTrust(f, { kind: 'web-identity', providerId: 'provider' });
    await expect(
      f.iam.api.roles.assume(owner, { tenantId: f.tenantId, trustId: web.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Partner',
      document: readDocuments,
    });
    const external = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
      externalId: 'partner-external-id',
    });
    for (const externalId of [undefined, 'wrong', 'partner-external-i', ''])
      await expect(
        f.iam.api.roles.assume(owner, {
          tenantId: f.tenantId,
          trustId: external.id,
          ...(externalId !== undefined ? { externalId } : {}),
        }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: external.id,
        externalId: 7 as unknown as string,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const partner = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: external.id,
      externalId: 'partner-external-id',
    });
    expect(partner.session.trustId).toBe(external.id);
  });

  it('refuses format and audience misuse without sts.jwt', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    const base = { tenantId: f.tenantId, trustId: trust.id };
    await expect(f.iam.api.roles.assume(owner, { ...base, format: 'jwt' })).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
      status: 403,
    });
    await expect(
      f.iam.api.roles.assume(owner, { ...base, format: 'paseto' as 'jwt' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.roles.assume(owner, { ...base, audience: ['http://localhost:3000/api/iam'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.roles.assume(owner, {
        ...base,
        format: 'opaque',
        audience: ['http://localhost:3000/api/iam'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('roles.assume with format jwt', () => {
  const issuer = 'http://localhost:3000/api/iam';
  const downstream = 'https://api.example.test';
  async function jwtFixture() {
    const key = generateTestKey('EdDSA', 'role-key');
    const sts: BetterIamOptions['sts'] = {
      jwt: {
        signingKeys: [key.privateJwk as never],
        audiences: [downstream],
        maxLifetimeSeconds: 600,
      },
    };
    return organizationFixture({ sts });
  }

  it('issues a signed session JWT backed by a stored row', async () => {
    const f = await jwtFixture();
    const { role, trust } = await ownerTrust(f, {
      allowedTagKeys: ['team'],
      sourceIdentityMode: 'optional',
    });
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      format: 'jwt',
      sessionName: 'jwt-session',
      sourceIdentity: 'alice',
      tags: { team: 'secret-team' },
      policy: readDocuments,
    });
    expect(assumed).toMatchObject({
      format: 'jwt',
      tokenType: 'Bearer',
      audience: [issuer],
      expiresIn: 600,
    });
    expect(assumed.token.split('.')).toHaveLength(3);
    const row = await sessionRow(f, assumed.session.id);
    expect(row).toMatchObject({
      format: 'jwt',
      audience: [issuer],
      tokenHash: sha256(assumed.token),
      uniqueKey: sha256(assumed.token),
    });
    const { header, payload } = decodeTestJwt(assumed.token);
    expect(header).toEqual({ alg: 'EdDSA', kid: 'role-key', typ: 'biam-session+jwt' });
    expect(payload).toEqual({
      iss: issuer,
      aud: issuer,
      sub: f.ownerId,
      tid: f.tenantId,
      sid: assumed.session.id,
      jti: assumed.session.id,
      iat: Math.floor(row.createdAt / 1000),
      nbf: Math.floor(row.createdAt / 1000),
      exp: Math.floor(row.expiresAt / 1000),
      auth_time: Math.floor(row.authenticatedAt / 1000),
      kind: 'role',
      mfa: false,
      role: role.id,
      trust: trust.id,
      src_tid: f.tenantId,
      session_name: 'jwt-session',
      source_identity: 'alice',
    });
    expect(assumed.token).not.toContain('secret-team');
    // Downstream services verify it offline with the published keys.
    const verifier = createSessionTokenVerifier({
      issuer,
      audience: issuer,
      jwks: f.iam.sessionTokens!.jwks(),
      now: f.now,
    });
    expect(await verifier.verify(assumed.token)).toMatchObject({ sid: assumed.session.id });
  });

  it('checks audiences against the allowlist and the drafted session’s permissions', async () => {
    const f = await jwtFixture();
    const owner = await f.ownerSignIn();
    const reader = await ownerTrust(f);
    const base = { tenantId: f.tenantId, trustId: reader.trust.id, format: 'jwt' as const };
    await expect(
      f.iam.api.roles.assume(owner, { ...base, audience: ['https://other.example.test'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(f.iam.api.roles.assume(owner, { ...base, audience: [] })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    // The role grants documents:read only, so the role session may not obtain tokens for the service.
    await expect(
      f.iam.api.roles.assume(owner, { ...base, audience: [downstream] }),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: `This credential may not obtain tokens for audience ${downstream}`,
    });
    const issuing = await ownerTrust(
      f,
      {},
      {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read', 'iam:assertions:create'],
            resources: ['*'],
          },
        ],
      },
    );
    const assumed = await f.iam.api.roles.assume(owner, {
      ...base,
      trustId: issuing.trust.id,
      audience: [downstream, issuer],
    });
    expect(assumed.audience).toEqual([downstream, issuer]);
    expect(decodeTestJwt(assumed.token).payload.aud).toEqual([downstream, issuer]);
  });

  it('refuses a duration above the JWT lifetime cap', async () => {
    const f = await jwtFixture();
    const owner = await f.ownerSignIn();
    const { trust } = await ownerTrust(f);
    await expect(
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: trust.id,
        format: 'jwt',
        durationSeconds: 900,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Opaque tokens are not bound by the JWT cap.
    const opaque = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
      durationSeconds: 900,
    });
    expect(opaque.expiresIn).toBe(900);
  });
});

describe("the 'role:assumed' audit event", () => {
  it('records the assumption in the target tenant while the source tenant keeps iam:roles:assume', async () => {
    const f = await organizationFixture();
    const platform = f.root.tenant.id;
    const password = 'a strong operator test password';
    const ops = await f.iam.api.identities.create(f.rootCredential, {
      tenantId: platform,
      email: 'ops@example.test',
      name: 'Ops',
      password,
    });
    const assumer = await f.iam.api.roles.create(f.rootCredential, {
      tenantId: platform,
      name: 'Assumer',
      permissions: ['iam:roles:assume'],
    });
    await f.iam.api.bindings.create(f.rootCredential, {
      tenantId: platform,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: ops.id,
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Support',
      document: readDocuments,
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
      roleId: role.id,
      requireMfa: false,
    });
    await patchTrust(f, trust.id, { allowedTagKeys: ['ticket', 'team'] });
    const login = await f.iam.api.auth.signIn({
      tenantId: platform,
      email: 'ops@example.test',
      password,
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const assumed = await f.iam.api.roles.assume(
      { token: login.token },
      {
        tenantId: f.tenantId,
        trustId: trust.id,
        sessionName: 'ticket-1234',
        tags: { ticket: 'T-1234', team: 'support' },
        durationSeconds: 1200,
      },
    );
    const target = await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId });
    const assumedEvents = target.filter((event) => event.action === 'role:assumed');
    expect(assumedEvents).toHaveLength(1);
    expect(assumedEvents[0]).toMatchObject({
      tenantId: f.tenantId,
      actorId: ops.id,
      originalActorId: ops.id,
      resourceId: role.id,
      outcome: 'allow',
      metadata: {
        trustId: trust.id,
        sourceTenantId: platform,
        sourceSessionKind: 'user',
        durationSeconds: 1200,
        format: 'opaque',
        tagKeys: ['team', 'ticket'],
      },
      sessionContext: {
        sessionId: assumed.session.id,
        kind: 'role',
        roleId: role.id,
        trustId: trust.id,
        sourceTenantId: platform,
        sessionName: 'ticket-1234',
      },
    });
    // Tag values never reach the audit trail; only their keys do.
    expect(JSON.stringify(assumedEvents[0])).not.toContain('T-1234');
    expect(target.some((event) => event.action === 'iam:roles:assume')).toBe(false);
    const source = await f.iam.store.find<AuditEvent>('audit', { tenantId: platform });
    const assume = source.filter((event) => event.action === 'iam:roles:assume');
    expect(assume).toHaveLength(1);
    expect(assume[0]).toMatchObject({
      actorId: ops.id,
      resourceId: role.id,
      outcome: 'allow',
      sessionContext: { sessionId: login.session.id, kind: 'user' },
    });
    expect(source.some((event) => event.action === 'role:assumed')).toBe(false);
  });

  it('is not recorded when the assumption is refused', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    await expect(
      f.iam.api.roles.assume(await f.ownerSignIn(), {
        tenantId: f.tenantId,
        trustId: trust.id,
        sourceIdentity: 'alice',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const events = await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(events.some((event) => event.action === 'role:assumed')).toBe(false);
  });
});

describe('prefixed API keys', () => {
  it('issues and rotates biam_key_ tokens', async () => {
    const f = await organizationFixture();
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    expect(key.token).toMatch(/^biam_key_[A-Za-z0-9_-]{49}$/);
    expect(parseCredentialToken(key.token)).toEqual({ type: 'key' });
    expect((await sessionRow(f, key.credentialId)).tokenHash).toBe(sha256(key.token));
    expect((await f.iam.authenticate({ token: key.token })).session.kind).toBe('api-key');
    f.advance(60_000);
    const rotated = await f.iam.api.credentials.rotate(f.ownerCredential, {
      tenantId: f.tenantId,
      credentialId: key.credentialId,
    });
    expect(rotated.token).toMatch(/^biam_key_[A-Za-z0-9_-]{49}$/);
    expect(rotated.token).not.toBe(key.token);
    const row = await sessionRow(f, rotated.credentialId);
    expect(row).toMatchObject({
      tokenHash: sha256(rotated.token),
      createdAt: f.now(),
      authenticatedAt: f.now(),
    });
    expect((await f.iam.authenticate({ token: rotated.token })).session.id).toBe(
      rotated.credentialId,
    );
    await expect(f.iam.authenticate({ token: key.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });
});
