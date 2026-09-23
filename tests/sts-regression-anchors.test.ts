import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument, PolicyStatement } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Regression anchors for temporary role credentials. They pin behaviour that holds before the STS round starts and
 * must keep holding after every wave of it: role chaining stays disabled, API-key sources work, scope-down policies
 * and trust ceilings bound the role, role lifetimes are validated and capped by the source credential,
 * `principal.sessionKind` tells role sessions apart, source attributes keep flowing through legacy and same-tenant
 * trusts, and revoking a trust ends its role credentials. Only public APIs are used, plus `iam.store` to put a trust
 * record into its legacy shape.
 */
function anchorFixture() {
  return organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { department: 'string' },
    },
  });
}

/** An allow statement over every resource, optionally conditioned. */
function allow(actions: string[], conditions?: PolicyStatement['conditions']): PolicyStatement {
  return { effect: 'allow', actions, resources: ['*'], ...(conditions ? { conditions } : {}) };
}
function policyDocument(...statements: PolicyStatement[]): PolicyDocument {
  return { version: 1, statements };
}

/** Whether `token` may perform `action` on a document of the Acme organization. */
async function allowed(f: OrganizationFixture, token: string, action: string): Promise<boolean> {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'anchor-document' },
    })
  ).allowed;
}

/** A role in Acme and a same-tenant trust from the owner to it that needs no MFA. */
async function ownerTrust(
  f: OrganizationFixture,
  role: PolicyDocument,
  trust: { ceiling?: PolicyDocument } = {},
) {
  const created = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Anchor role',
    document: role,
  });
  const relationship = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: created.id,
    requireMfa: false,
    ...trust,
  });
  return { role: created, trust: relationship };
}

/**
 * A service account in Acme whose own binding allows writing documents and assuming roles, and a same-tenant trust
 * (no MFA) from it to a role that only reads documents.
 */
async function serviceAccountTrust(f: OrganizationFixture) {
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'deployer',
  });
  const own = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Deployer',
    document: policyDocument(allow(['documents:write', 'iam:roles:assume'])),
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
    document: policyDocument(allow(['documents:read'])),
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: account.id,
    roleId: reader.id,
    requireMfa: false,
  });
  return { account, trust };
}

describe('STS regression anchors', () => {
  it('(a) refuses to assume a role from a role credential', async () => {
    const f = await anchorFixture();
    const { trust } = await ownerTrust(f, policyDocument(allow(['documents:read'])));
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    await expect(
      f.iam.api.roles.assume({ token: assumed.token }, { tenantId: f.tenantId, trustId: trust.id }),
    ).rejects.toMatchObject({ code: 'ROLE_CHAINING_DISABLED', status: 400 });
  });

  it("(b) lets an API key assume a role that acts with the role's grants only", async () => {
    const f = await anchorFixture();
    const { account, trust } = await serviceAccountTrust(f);
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    // The key itself acts under the account's own binding.
    expect(await allowed(f, key.token, 'documents:write')).toBe(true);
    expect(await allowed(f, key.token, 'documents:read')).toBe(false);
    const assumed = await f.iam.api.roles.assume(
      { token: key.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    expect(assumed.session.roleId).toBe(trust.roleId);
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    expect(await allowed(f, assumed.token, 'documents:write')).toBe(false);
  });

  it('(c) bounds the role by the policy passed when assuming it', async () => {
    const f = await anchorFixture();
    const { trust } = await ownerTrust(
      f,
      policyDocument(allow(['documents:read', 'documents:write'])),
    );
    const full = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(await allowed(f, full.token, 'documents:write')).toBe(true);
    const scoped = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      policy: policyDocument(allow(['documents:read'])),
    });
    expect(await allowed(f, scoped.token, 'documents:read')).toBe(true);
    expect(await allowed(f, scoped.token, 'documents:write')).toBe(false);
  });

  it("(d) bounds the role by the trust's ceiling", async () => {
    const f = await anchorFixture();
    const { trust } = await ownerTrust(
      f,
      policyDocument(allow(['documents:read', 'documents:write'])),
      {
        ceiling: policyDocument(allow(['documents:read'])),
      },
    );
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    expect(await allowed(f, assumed.token, 'documents:write')).toBe(false);
  });

  it('(e) never outlives the source API key', async () => {
    const f = await anchorFixture();
    const { account, trust } = await serviceAccountTrust(f);
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
      expiresInSeconds: 120,
    });
    const assumed = await f.iam.api.roles.assume(
      { token: key.token },
      { tenantId: f.tenantId, trustId: trust.id, durationSeconds: 900 },
    );
    expect(assumed.session.expiresAt).toBe(key.expiresAt);
  });

  it('(f) validates the requested duration and defaults to 15 minutes', async () => {
    const f = await anchorFixture();
    const { trust } = await ownerTrust(f, policyDocument(allow(['documents:read'])));
    const owner = await f.ownerSignIn();
    for (const durationSeconds of [59, 3601])
      await expect(
        f.iam.api.roles.assume(owner, { tenantId: f.tenantId, trustId: trust.id, durationSeconds }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The bounds themselves are inclusive: one minute and one hour are both accepted.
    for (const durationSeconds of [60, 3600]) {
      const bounded = await f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: trust.id,
        durationSeconds,
      });
      expect(bounded.session.expiresAt).toBe(f.now() + durationSeconds * 1000);
    }
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(assumed.session.expiresAt).toBe(f.now() + 900_000);
  });

  it('(g) exposes the session kind to policy conditions', async () => {
    const f = await anchorFixture();
    const alice = await f.member('alice');
    const assumer = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assumer',
      document: policyDocument(allow(['iam:roles:assume'])),
    });
    const roleOnly = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Role-only reader',
      document: policyDocument(
        allow(['documents:read'], { StringEquals: { 'principal.sessionKind': 'role' } }),
      ),
    });
    for (const role of [assumer, roleOnly])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: alice.id,
      });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: alice.id,
      roleId: roleOnly.id,
      requireMfa: false,
    });
    const session = await f.signIn('alice');
    const assumed = await f.iam.api.roles.assume(
      { token: session.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    expect(await allowed(f, session.token, 'documents:read')).toBe(false);
  });

  it('(h) passes source attributes through a legacy cross-tenant trust', async () => {
    const f = await anchorFixture();
    const platform = f.root.tenant.id;
    const password = 'a strong operator test password';
    const ops = await f.iam.api.identities.create(f.rootCredential, {
      tenantId: platform,
      email: 'ops@example.test',
      name: 'Ops',
      password,
    });
    await f.iam.api.identities.update(f.rootCredential, {
      tenantId: platform,
      identityId: ops.id,
      attributes: { department: 'eng' },
    });
    const assumer = await f.iam.api.roles.create(f.rootCredential, {
      tenantId: platform,
      name: 'Assumer',
      document: policyDocument(allow(['iam:roles:assume'])),
    });
    await f.iam.api.bindings.create(f.rootCredential, {
      tenantId: platform,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: ops.id,
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Engineering reader',
      document: policyDocument(
        allow(['documents:read'], { StringEquals: { 'principal.department': 'eng' } }),
        allow(['documents:write'], { StringEquals: { 'principal.department': 'sales' } }),
      ),
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
      roleId: role.id,
      requireMfa: false,
    });
    // Records written before `passSourceAttributes` existed have no such field.
    await f.iam.store.transaction(async (tx) => {
      const legacy = { ...(await tx.get('trusts', trust.id))! };
      delete legacy.passSourceAttributes;
      await tx.put('trusts', legacy);
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: platform,
      email: 'ops@example.test',
      password,
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const assumed = await f.iam.api.roles.assume(
      { token: login.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    expect(await allowed(f, assumed.token, 'documents:write')).toBe(false);
  });

  it('(i) passes source attributes through a same-tenant trust', async () => {
    const f = await anchorFixture();
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: f.ownerId,
      attributes: { department: 'eng' },
    });
    const { trust } = await ownerTrust(
      f,
      policyDocument(
        allow(['documents:read'], { StringEquals: { 'principal.department': 'eng' } }),
        allow(['documents:write'], { StringEquals: { 'principal.department': 'sales' } }),
      ),
    );
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    expect(await allowed(f, assumed.token, 'documents:write')).toBe(false);
  });

  it('(j) ends role credentials when their trust is revoked', async () => {
    const f = await anchorFixture();
    const { trust } = await ownerTrust(f, policyDocument(allow(['documents:read'])));
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect((await f.iam.authenticate({ token: assumed.token })).session.kind).toBe('role');
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    await f.iam.api.trust.revoke(f.rootCredential, { tenantId: f.tenantId, trustId: trust.id });
    await expect(f.iam.authenticate({ token: assumed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      status: 401,
    });
    // Authorization refuses the revoked token too: it authenticates first, so it fails with the same 401.
    await expect(allowed(f, assumed.token, 'documents:read')).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      status: 401,
    });
  });
});
