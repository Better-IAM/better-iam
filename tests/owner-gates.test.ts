import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument } from '@better-iam/core';
import type { PublicJwk } from '../packages/server/src/models.js';
import { generateTestKey, signTestJwt } from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * An owner of one tenant who assumes a role in another tenant acts with that role's permissions only. The
 * ownership of the source account must not satisfy the target tenant's owner gates or `principal.owner`
 * policy conditions ("do not carry source-tenant permissions into the target session").
 */
async function crossTenantRole() {
  const f = await organizationFixture();
  const beta = await f.iam.api.tenants.create(f.rootCredential, {
    parentId: f.root.tenant.id,
    name: 'Beta',
    type: 'organization',
    ownerEmail: 'owner@beta.test',
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === beta.tenant.id && message.template === 'owner-invitation',
  )!;
  const betaOwner = await f.iam.api.tenants.acceptInvitation({
    tenantId: beta.tenant.id,
    token: invitation.payload.token!,
    name: 'Beta owner',
    password: 'a strong beta owner password',
  });
  if (!('token' in betaOwner)) throw new Error('Unexpected MFA');
  const betaCredential = { token: betaOwner.token };
  const betaId = beta.tenant.id;
  const second = await f.iam.api.identities.create(betaCredential, {
    tenantId: betaId,
    email: 'second@beta.test',
    name: 'Second owner',
    password: 'a strong second owner password',
  });
  await f.iam.api.identities.setOwner(betaCredential, {
    tenantId: betaId,
    identityId: second.id,
    owner: true,
  });
  const role = await f.iam.api.roles.create(betaCredential, {
    tenantId: betaId,
    name: 'Contractor administration',
    document: {
      version: 1,
      statements: [
        { effect: 'allow', actions: ['iam:identities:update'], resources: ['*'] },
        {
          sid: 'OwnersRead',
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['*'],
          conditions: { Bool: { 'principal.owner': true } },
        },
      ],
    },
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: betaId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
    tenantId: betaId,
    trustId: trust.id,
  });
  return { f, betaId, betaCredential, second, assumed: { token: assumed.token } };
}

describe('owner gates across tenants', () => {
  it('refuses ownership changes from an assumed role held by another tenant’s owner', async () => {
    const { f, betaId, betaCredential, second, assumed } = await crossTenantRole();
    // setOwner and offboard require a recent authentication before the owner gate runs, and a role session is a
    // temporary credential that never passes that check, so the refusal is RECENT_AUTH_REQUIRED rather than the
    // owner gate's ACCESS_DENIED. Either way the source tenant's ownership does not reach the target tenant.
    await expect(
      f.iam.api.identities.setOwner(assumed, {
        tenantId: betaId,
        identityId: second.id,
        owner: false,
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    await expect(
      f.iam.api.identities.offboard(assumed, {
        tenantId: betaId,
        identityId: second.id,
        reason: 'contract ended',
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const listed = await f.iam.api.identities.list(betaCredential, { tenantId: betaId });
    expect(listed.find((identity) => identity.id === second.id)).toMatchObject({
      owner: true,
      status: 'active',
    });
    // An owner of the tenant itself still can.
    await f.iam.api.identities.setOwner(betaCredential, {
      tenantId: betaId,
      identityId: second.id,
      owner: false,
    });
  });

  it('does not report the source account as an owner to the target tenant’s policies', async () => {
    const { f, betaId, betaCredential, assumed } = await crossTenantRole();
    const request = {
      tenantId: betaId,
      action: 'documents:read',
      resource: { type: 'document', id: 'contract' },
    };
    expect((await f.iam.authorize({ ...assumed, ...request })).allowed).toBe(false);
    expect((await f.iam.authorize({ ...betaCredential, ...request })).allowed).toBe(true);
  });
});

/**
 * Probes `principal.owner` and `principal.rootAdmin` through explicit denies: `document/owner-only` is denied unless
 * the principal is an owner, `document/root-only` unless it is a root administrator, and everything else is readable.
 * A `Bool` condition on a key that is absent never matches, so a refusal proves the key is present and `false`.
 */
const flagProbe: PolicyDocument = {
  version: 1,
  statements: [
    { effect: 'allow', actions: ['documents:read'], resources: ['*'] },
    {
      sid: 'NotOwner',
      effect: 'deny',
      actions: ['documents:read'],
      resources: ['document/owner-only'],
      conditions: { Bool: { 'principal.owner': false } },
    },
    {
      sid: 'NotRootAdmin',
      effect: 'deny',
      actions: ['documents:read'],
      resources: ['document/root-only'],
      conditions: { Bool: { 'principal.rootAdmin': false } },
    },
  ],
};

/** Binds the flag probe to `identityId` in `tenantId`, as `credential`. */
async function bindProbe(
  f: OrganizationFixture,
  credential: { token: string },
  tenantId: string,
  identityId: string,
) {
  const role = await f.iam.api.roles.create(credential, {
    tenantId,
    name: 'Flag probe',
    document: flagProbe,
  });
  await f.iam.api.bindings.create(credential, {
    tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identityId,
  });
}

async function reads(f: OrganizationFixture, token: string, tenantId: string, id: string) {
  return f.iam.authorize({
    token,
    tenantId,
    action: 'documents:read',
    resource: { type: 'document', id },
  });
}

describe('owner and root flags on temporary credentials', () => {
  it('never makes an owner’s session token (opaque or JWT) an owner or root administrator', async () => {
    const f = await organizationFixture({
      sts: { jwt: { signingKeys: [generateTestKey('EdDSA', 'k1').privateJwk as never] } },
    });
    await bindProbe(f, f.ownerCredential, f.tenantId, f.ownerId);
    // The owner's own session is the owner (and not a root administrator).
    const own = f.ownerCredential.token;
    expect((await reads(f, own, f.tenantId, 'owner-only')).allowed).toBe(true);
    expect((await reads(f, own, f.tenantId, 'root-only')).allowed).toBe(false);
    for (const format of ['opaque', 'jwt'] as const) {
      const issued = await f.iam.api.sts.getSessionToken(f.ownerCredential, { format });
      expect((await reads(f, issued.token, f.tenantId, 'plain')).allowed).toBe(true);
      expect((await reads(f, issued.token, f.tenantId, 'owner-only')).allowed).toBe(false);
      expect((await reads(f, issued.token, f.tenantId, 'root-only')).allowed).toBe(false);
      // Owner gates refuse it too: ownership changes need a signed-in session.
      const alice = await f.member(`alice-${format}`);
      await expect(
        f.iam.api.identities.setOwner(
          { token: issued.token },
          { tenantId: f.tenantId, identityId: alice.id, owner: true },
        ),
      ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    }
  });

  it('never makes a web-identity session an owner or root administrator', async () => {
    const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
    const idp = generateTestKey('ES256', 'idp');
    const issuer = 'https://token.actions.example.test';
    const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'CI',
      issuer,
      audiences: ['acme'],
      jwks: { keys: [idp.publicJwk as PublicJwk] },
    });
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Probe role',
      document: flagProbe,
    });
    const trust = await f.iam.api.trust.create(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'web-identity',
      providerId: provider.id,
      serviceAccountId: account.id,
      roleId: role.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app' } },
    });
    const iat = Math.floor(f.now() / 1000);
    const web = await f.iam.api.sts.assumeRoleWithWebIdentity({
      tenantId: f.tenantId,
      trustId: trust.id,
      sessionName: 'ci-run',
      webIdentityToken: signTestJwt(idp, {
        iss: issuer,
        aud: 'acme',
        sub: 'repo:acme/app',
        iat,
        exp: iat + 300,
      }),
    });
    expect((await reads(f, web.token, f.tenantId, 'plain')).allowed).toBe(true);
    expect((await reads(f, web.token, f.tenantId, 'owner-only')).allowed).toBe(false);
    expect((await reads(f, web.token, f.tenantId, 'root-only')).allowed).toBe(false);
  });

  it('never gives a root administrator’s session token the root override', async () => {
    const f = await organizationFixture({
      sts: { jwt: { signingKeys: [generateTestKey('ES256', 'k1').privateJwk as never] } },
    });
    const platform = f.root.tenant.id;
    await bindProbe(f, f.rootCredential, platform, f.root.identity.id);
    // The root administrator's own MFA session overrides everywhere.
    for (const tenantId of [platform, f.tenantId])
      expect(await reads(f, f.rootCredential.token, tenantId, 'root-only')).toMatchObject({
        allowed: true,
        reason: 'ROOT_OVERRIDE',
      });
    for (const format of ['opaque', 'jwt'] as const) {
      const issued = await f.iam.api.sts.getSessionToken(f.rootCredential, { format });
      expect(issued.session.mfa).toBe(true);
      for (const id of ['plain', 'owner-only', 'root-only']) {
        const decision = await reads(f, issued.token, platform, id);
        expect(decision.reason).not.toBe('ROOT_OVERRIDE');
        expect(decision.allowed).toBe(id === 'plain');
      }
      const elsewhere = await reads(f, issued.token, f.tenantId, 'plain');
      expect(elsewhere).toMatchObject({ allowed: false });
      expect(elsewhere.reason).not.toBe('ROOT_OVERRIDE');
      // Root-only operations refuse it as well.
      await expect(
        f.iam.api.root.listAdministrators({ token: issued.token }, { tenantId: platform }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    }
  });
});
