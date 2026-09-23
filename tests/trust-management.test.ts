import { createHash, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, PolicyDocument, Session } from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import type { OidcProvider, Trust } from '../packages/server/src/models.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Trust management: `trust.create` defaults and validation of the AssumeRole knobs, PublicTrust projections without
 * external ID hashes, `trust.update` (root-only for identity trusts, CONFLICT when revoked, INVALID_INPUT on a no-op,
 * watermark bumps when the trust tightens), passSourceAttributes on real cross-tenant sessions, `roles.listSessions`,
 * the 'trust-passes-foreign-attributes' analysis finding, and the fail-closed reading of malformed stored trust knobs
 * in `roles.assume` (patched through `iam.store`).
 */

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const all: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
};
const readDocuments: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
};
const publicTrustKeys = [
  'allowedTagKeys',
  'ceiling',
  'createdAt',
  'createdBy',
  'id',
  'kind',
  'passSourceAttributes',
  'requireMfa',
  'requiresExternalId',
  'revoked',
  'roleId',
  'sourceIdentityId',
  'sourceIdentityMode',
  'sourceTenantId',
  'tenantId',
  'updatedAt',
];

/** Replaces fields of a stored record; an `undefined` value removes the field. */
async function patch(
  f: OrganizationFixture,
  collection: string,
  recordId: string,
  fields: Record<string, unknown>,
) {
  await f.iam.store.transaction(async (tx) => {
    const current = (await tx.get(collection, recordId))!;
    const next: Record<string, unknown> = { ...current, ...fields };
    for (const [key, value] of Object.entries(fields)) if (value === undefined) delete next[key];
    await tx.put(collection, next as never);
  });
}

/** A reader role the owner creates, under the owner's own grant authority. */
async function readerRole(f: OrganizationFixture, document: PolicyDocument = readDocuments) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Reader ${randomUUID().slice(0, 8)}`,
    document,
  });
  return { ...role, authorityId: role.authorityId as string };
}

/** A reader role and a same-tenant trust (no MFA) from the owner to it. */
async function ownerTrust(f: OrganizationFixture, extra: Record<string, unknown> = {}) {
  const role = await readerRole(f);
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
    ...extra,
  });
  return { role, trust };
}

/** A platform operator allowed to assume roles, optionally with identity attributes, and a way to sign in. */
async function platformOperator(f: OrganizationFixture, attributes?: Record<string, string>) {
  const platform = f.root.tenant.id;
  const password = 'a strong operator test password';
  const ops = await f.iam.api.identities.create(f.rootCredential, {
    tenantId: platform,
    email: 'ops@example.test',
    name: 'Ops',
    password,
  });
  if (attributes)
    await f.iam.api.identities.update(f.rootCredential, {
      tenantId: platform,
      identityId: ops.id,
      attributes,
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
  const signIn = async () => {
    const login = await f.iam.api.auth.signIn({
      tenantId: platform,
      email: 'ops@example.test',
      password,
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    return { token: login.token };
  };
  return { platform, ops, signIn };
}

async function works(f: OrganizationFixture, token: string): Promise<boolean> {
  try {
    await f.iam.authenticate({ token });
    return true;
  } catch {
    return false;
  }
}

async function allowed(f: OrganizationFixture, token: string, action: string): Promise<boolean> {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'trust-document' },
    })
  ).allowed;
}

/** Seeds a web-identity trust record, as the Wave 4 API will store it. */
async function seedWebTrust(
  f: OrganizationFixture,
  roleId: string,
  fields: Partial<Trust> = {},
): Promise<Trust> {
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `workload-${randomUUID().slice(0, 8)}`,
  });
  const now = f.now();
  const trust: Trust = {
    id: randomUUID(),
    tenantId: f.tenantId,
    kind: 'web-identity',
    sourceTenantId: f.tenantId,
    sourceIdentityId: account.id,
    roleId,
    requireMfa: false,
    revoked: false,
    ceiling: all,
    passSourceAttributes: true,
    providerId: randomUUID(),
    conditions: { StringEquals: { 'token.sub': 'repo:acme/app:ref:refs/heads/main' } },
    createdAt: now,
    createdBy: f.ownerId,
    updatedAt: now,
    ...fields,
  };
  await f.iam.store.transaction((tx) => tx.insert('trusts', trust));
  return trust;
}

describe('trust.create', () => {
  it('returns a PublicTrust with the identity defaults and never the external ID hash', async () => {
    const f = await organizationFixture();
    const role = await readerRole(f);
    const created = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      externalId: 'contract-7',
    });
    expect(Object.keys(created).sort()).toEqual(publicTrustKeys);
    expect(created).toEqual({
      id: created.id,
      tenantId: f.tenantId,
      kind: 'identity',
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: true,
      requiresExternalId: true,
      revoked: false,
      ceiling: all,
      passSourceAttributes: true,
      allowedTagKeys: [],
      sourceIdentityMode: 'forbidden',
      createdAt: f.now(),
      createdBy: f.root.identity.id,
      updatedAt: f.now(),
    });
    const stored = (await f.iam.store.get<Trust>('trusts', created.id))!;
    expect(stored.externalIdHash).toBe(sha256('contract-7'));
    const listed = await f.iam.api.trust.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(listed).toEqual([created]);
    expect(JSON.stringify(listed)).not.toContain('externalIdHash');
    expect(JSON.stringify(listed)).not.toContain(stored.externalIdHash!);
  });

  it('keeps source attributes out of new cross-tenant trusts unless asked', async () => {
    const f = await organizationFixture();
    const { platform, ops } = await platformOperator(f);
    const role = await readerRole(f);
    const base = { tenantId: f.tenantId, sourceTenantId: platform, sourceIdentityId: ops.id };
    const closed = await f.iam.api.trust.create(f.rootCredential, { ...base, roleId: role.id });
    expect(closed).toMatchObject({ passSourceAttributes: false, requiresExternalId: false });
    const open = await f.iam.api.trust.create(f.rootCredential, {
      ...base,
      roleId: role.id,
      passSourceAttributes: true,
    });
    expect(open.passSourceAttributes).toBe(true);
  });

  it('validates the new knobs', async () => {
    const f = await organizationFixture({ sts: { maxRoleSessionSeconds: 7200 } });
    const role = await readerRole(f);
    const base = {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
    };
    const invalid: Record<string, unknown>[] = [
      { maxSessionSeconds: 59 },
      { maxSessionSeconds: 7201 },
      { maxSessionSeconds: 900.5 },
      { maxSessionSeconds: '900' },
      { allowedTagKeys: 'team' },
      { allowedTagKeys: ['team', 'Team'] },
      { allowedTagKeys: ['*', 'team'] },
      { allowedTagKeys: ['bad-key'] },
      { allowedTagKeys: Array.from({ length: 51 }, (_, index) => `key${index}`) },
      { sourceIdentityMode: 'sometimes' },
      { passSourceAttributes: 'yes' },
      { requireMfa: 'no' },
      { description: 'x'.repeat(513) },
      { description: '' },
      { externalId: 42 },
      { kind: 'saml' },
    ];
    for (const extra of invalid)
      await expect(
        f.iam.api.trust.create(f.rootCredential, { ...base, ...extra } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Web-identity trusts are gated by sts.webIdentity (off in this fixture); the gate is checked first.
    await expect(
      f.iam.api.trust.create(f.rootCredential, { ...base, kind: 'web-identity' } as never),
    ).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
      message: 'Web identity federation is not enabled',
    });
    const configured = await f.iam.api.trust.create(f.rootCredential, {
      ...base,
      kind: 'identity',
      maxSessionSeconds: 7200,
      allowedTagKeys: ['team', 'env'],
      sourceIdentityMode: 'required',
      passSourceAttributes: false,
      description: 'Break-glass access for the on-call engineer',
    });
    expect(configured).toMatchObject({
      maxSessionSeconds: 7200,
      allowedTagKeys: ['team', 'env'],
      sourceIdentityMode: 'required',
      passSourceAttributes: false,
      description: 'Break-glass access for the on-call engineer',
    });
    const wildcard = await f.iam.api.trust.create(f.rootCredential, {
      ...base,
      allowedTagKeys: ['*'],
    });
    expect(wildcard.allowedTagKeys).toEqual(['*']);
    // Identity trusts stay platform-controlled.
    await expect(f.iam.api.trust.create(await f.ownerSignIn(), base)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
  });
});

describe('trust.update', () => {
  it('bumps the watermark only when the trust tightens', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f, { allowedTagKeys: ['team'] });
    const update = (fields: Record<string, unknown>) =>
      f.iam.api.trust.update(f.rootCredential, {
        tenantId: f.tenantId,
        trustId: trust.id,
        ...fields,
      });
    const assume = async () =>
      (
        await f.iam.api.roles.assume(await f.ownerSignIn(), {
          tenantId: f.tenantId,
          trustId: trust.id,
        })
      ).token;
    const first = await assume();
    f.advance(1000);
    // Loosening or relabelling keeps live sessions.
    for (const fields of [
      { description: 'Support access' },
      { passSourceAttributes: false },
      { requireMfa: false, description: 'Support access for tickets' },
      { ceiling: readDocuments },
    ]) {
      const updated = await update(fields);
      expect(updated.sessionsRevokedBefore).toBeUndefined();
      expect(updated.updatedAt).toBe(f.now());
    }
    expect(await works(f, first)).toBe(true);
    // A lower session cap ends the sessions issued under the higher one.
    const capped = await update({ maxSessionSeconds: 1800 });
    expect(capped).toMatchObject({ maxSessionSeconds: 1800, sessionsRevokedBefore: f.now() + 1 });
    expect(await works(f, first)).toBe(false);
    f.advance(1000);
    const second = await assume();
    // Raising it again (or clearing it back to the 3600 s default) does not.
    const raised = await update({ maxSessionSeconds: null });
    expect(raised).not.toHaveProperty('maxSessionSeconds');
    expect(raised.sessionsRevokedBefore).toBe(capped.sessionsRevokedBefore);
    expect(await works(f, second)).toBe(true);
    // Tag keys (compared as a set) and the source identity mode bump it.
    await expect(update({ allowedTagKeys: ['team'] })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    const tagged = await update({ allowedTagKeys: ['team', 'env'] });
    expect(tagged.sessionsRevokedBefore).toBe(f.now() + 1);
    expect(await works(f, second)).toBe(false);
    f.advance(1000);
    const third = await assume();
    const moded = await update({ sourceIdentityMode: 'optional' });
    expect(moded.sessionsRevokedBefore).toBe(f.now() + 1);
    expect(await works(f, third)).toBe(false);
    f.advance(1000);
    const cleared = await update({ allowedTagKeys: null, description: null });
    expect(cleared.allowedTagKeys).toEqual([]);
    expect(cleared).not.toHaveProperty('description');
    expect(cleared.sessionsRevokedBefore).toBe(f.now() + 1);
    expect(cleared).not.toHaveProperty('externalIdHash');
  });

  it('refuses non-root callers, no-ops, foreign fields, revoked trusts and stale sessions', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f, { description: 'Support' });
    const base = { tenantId: f.tenantId, trustId: trust.id };
    // The owner holds iam:trust:update but identity trusts are platform-controlled; the refusal is audited.
    await expect(
      f.iam.api.trust.update(await f.ownerSignIn(), { ...base, description: 'Mine' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const denials = (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
      (event) => event.action === 'iam:trust:update' && event.outcome === 'deny',
    );
    expect(denials).toHaveLength(1);
    for (const fields of [
      {},
      { description: 'Support' },
      { requireMfa: false },
      { maxSessionSeconds: 3601 },
      { maxSessionSeconds: 30 },
      { sourceIdentityMode: 'maybe' },
      { conditions: { StringEquals: { 'token.sub': 'repo:acme/app' } } },
      { tagClaims: { team: 'token.team' } },
      { sourceIdentityClaim: 'token.actor' },
    ])
      await expect(
        f.iam.api.trust.update(f.rootCredential, { ...base, ...fields } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.trust.update(f.rootCredential, {
        tenantId: f.tenantId,
        trustId: randomUUID(),
        description: 'x',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const revoked = await f.iam.api.trust.revoke(f.rootCredential, base);
    expect(revoked.revoked).toBe(true);
    await expect(
      f.iam.api.trust.update(f.rootCredential, { ...base, description: 'Again' }),
    ).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.trust.update(f.rootCredential, { ...base, description: 'Late' }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('manages web-identity trusts through the creator authority and their own fields', async () => {
    const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
    const role = await readerRole(f);
    const authorityId = role.authorityId!;
    const mine = await seedWebTrust(f, role.id, { authorityId });
    const owner = await f.ownerSignIn();
    const base = { tenantId: f.tenantId, trustId: mine.id };
    for (const fields of [
      { requireMfa: true },
      { allowedTagKeys: ['team'] },
      { sourceIdentityMode: 'optional' },
      { tagClaims: { 'bad-key': 'token.team' } },
      { tagClaims: { team: 'team' } },
      { sourceIdentityClaim: 'actor' },
    ])
      await expect(
        f.iam.api.trust.update(owner, { ...base, ...fields } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.trust.update(owner, {
        ...base,
        conditions: { StringLike: { 'token.sub': '*' } },
      }),
    ).rejects.toMatchObject({ code: 'WEAK_TRUST_CONDITIONS' });
    // The creator's authority edits the trust (no root needed); a claim mapping change revokes older sessions.
    const described = await f.iam.api.trust.update(owner, { ...base, description: 'CI deploys' });
    expect(described).toMatchObject({ kind: 'web-identity', description: 'CI deploys' });
    expect(described.sessionsRevokedBefore).toBeUndefined();
    const mapped = await f.iam.api.trust.update(owner, {
      ...base,
      tagClaims: { repo: 'token.repository' },
      sourceIdentityClaim: 'token.actor',
    });
    expect(mapped).toMatchObject({
      tagClaims: { repo: 'token.repository' },
      sourceIdentityClaim: 'token.actor',
      sessionsRevokedBefore: f.now() + 1,
    });
    // A trust issued under another administrator's authority is out of the owner's reach.
    const rootRole = await f.iam.api.roles.create(f.rootCredential, {
      tenantId: f.tenantId,
      name: 'Platform reader',
      document: readDocuments,
    });
    expect(rootRole.authorityId).not.toBe(authorityId);
    const foreign = await seedWebTrust(f, rootRole.id, {
      authorityId: rootRole.authorityId as string,
    });
    await expect(
      f.iam.api.trust.update(owner, {
        tenantId: f.tenantId,
        trustId: foreign.id,
        description: 'Mine now',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.trust.revoke(owner, { tenantId: f.tenantId, trustId: foreign.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const revoked = await f.iam.api.trust.revoke(owner, base);
    expect(revoked).toMatchObject({ kind: 'web-identity', revoked: true });
  });

  it('is unavailable for web-identity trusts while the feature is off', async () => {
    const f = await organizationFixture();
    const role = await readerRole(f);
    const web = await seedWebTrust(f, role.id, { authorityId: role.authorityId });
    await expect(
      f.iam.api.trust.update(f.rootCredential, {
        tenantId: f.tenantId,
        trustId: web.id,
        description: 'x',
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED', status: 403 });
  });
});

describe('passSourceAttributes', () => {
  it('hides the source account’s attributes from a real cross-tenant role session until the trust opts in', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        identityAttributes: { department: 'string' },
      },
    });
    const { platform, ops, signIn } = await platformOperator(f, { department: 'eng' });
    const role = await readerRole(f, {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['*'],
          conditions: { StringEquals: { 'principal.department': 'eng' } },
        },
      ],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
      roleId: role.id,
      requireMfa: false,
    });
    expect(trust.passSourceAttributes).toBe(false);
    const assumed = await f.iam.api.roles.assume(await signIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(false);
    const opened = await f.iam.api.trust.update(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: trust.id,
      passSourceAttributes: true,
    });
    expect(opened.sessionsRevokedBefore).toBeUndefined();
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
  });
});

describe('roles.listSessions', () => {
  it('lists live role sessions newest first as allowlist summaries, with filters and exclusions', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const sibling = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const other = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    const assume = (trustId: string, sessionName?: string) =>
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId,
        ...(sessionName ? { sessionName } : {}),
      });
    const first = await assume(trust.id, 'first-session');
    f.advance(1000);
    const second = await assume(sibling.id);
    f.advance(1000);
    const third = await assume(other.trust.id);
    const list = (input: Record<string, unknown> = {}) =>
      f.iam.api.roles.listSessions(f.ownerCredential, { tenantId: f.tenantId, ...input });
    const everything = await list();
    expect(everything.map((summary) => summary.id)).toEqual([
      third.session.id,
      second.session.id,
      first.session.id,
    ]);
    const summary = everything[2]!;
    expect(summary).toEqual({
      id: first.session.id,
      roleId: role.id,
      trustId: trust.id,
      identityId: f.ownerId,
      sourceTenantId: f.tenantId,
      sessionName: 'first-session',
      mfa: false,
      format: 'opaque',
      createdAt: first.session.expiresAt - 900_000,
      expiresAt: first.session.expiresAt,
    });
    const serialized = JSON.stringify(everything);
    for (const secret of [
      'tokenHash',
      'uniqueKey',
      'policy',
      'sourcePolicy',
      'credentialAuthorityId',
      'sourceAuthorityIds',
      'sourceSessionId',
      first.token,
    ])
      expect(serialized).not.toContain(secret);
    expect((await list({ roleId: role.id })).map((item) => item.id)).toEqual([
      second.session.id,
      first.session.id,
    ]);
    expect((await list({ trustId: trust.id })).map((item) => item.id)).toEqual([first.session.id]);
    expect(await list({ roleId: other.role.id, trustId: trust.id })).toEqual([]);
    expect((await list({ limit: 1 })).map((item) => item.id)).toEqual([third.session.id]);
    for (const limit of [0, 501, 1.5])
      await expect(list({ limit })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(list({ roleId: randomUUID() })).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Exclusions: a revoked trust, a trust watermark, a web session under a provider watermark, expiry.
    await patch(f, 'trusts', sibling.id, { revoked: true });
    await patch(f, 'trusts', other.trust.id, { sessionsRevokedBefore: third.session.expiresAt });
    const web = await seedWebTrust(f, role.id, { authorityId: role.authorityId });
    const provider = {
      id: web.providerId!,
      tenantId: f.tenantId,
      uniqueKey: `issuer:https://token.example.test/${web.providerId}`,
      name: 'CI',
      issuer: `https://token.example.test/${web.providerId}`,
      audiences: ['sts.example.test'],
      algorithms: ['RS256'],
      maxTokenLifetimeSeconds: 3600,
      clockToleranceSeconds: 30,
      replayProtection: 'single-use',
      enabled: true,
      authorityId: role.authorityId!,
      createdAt: f.now(),
      createdBy: f.ownerId,
      updatedAt: f.now(),
    } satisfies OidcProvider;
    const webSession = (createdAt: number, subject: string): Session => ({
      id: randomUUID(),
      tenantId: f.tenantId,
      identityId: web.sourceIdentityId,
      originalIdentityId: web.sourceIdentityId,
      roleId: role.id,
      trustId: web.id,
      kind: 'role',
      tokenHash: sha256(randomUUID()),
      createdAt,
      lastSeenAt: createdAt,
      authenticatedAt: createdAt,
      expiresAt: createdAt + 900_000,
      mfa: false,
      sessionName: 'ci-run',
      credentialAuthorityId: role.authorityId,
      webIdentity: { providerId: provider.id, issuer: provider.issuer, subject },
      client: { ip: '203.0.113.7' },
    });
    const stale = webSession(f.now() - 500, 'repo:acme/app:old');
    const fresh = webSession(f.now(), 'repo:acme/app:new');
    await f.iam.store.transaction(async (tx) => {
      await tx.insert('oidcProviders', { ...provider, sessionsRevokedBefore: f.now() - 100 });
      await tx.insert('sessions', { ...stale, uniqueKey: stale.tokenHash });
      await tx.insert('sessions', { ...fresh, uniqueKey: fresh.tokenHash });
    });
    const remaining = await list();
    expect(remaining.map((item) => item.id)).toEqual([fresh.id, first.session.id]);
    expect(remaining[0]).toEqual({
      id: fresh.id,
      roleId: role.id,
      trustId: web.id,
      identityId: web.sourceIdentityId,
      sessionName: 'ci-run',
      webIdentity: { providerId: provider.id, subject: 'repo:acme/app:new' },
      mfa: false,
      format: 'opaque',
      createdAt: fresh.createdAt,
      expiresAt: fresh.expiresAt,
      clientIp: '203.0.113.7',
    });
    f.advance(900_000);
    expect(await list()).toEqual([]);
  });

  it('requires iam:trust:read', async () => {
    const f = await organizationFixture();
    const { role } = await ownerTrust(f);
    await f.member('alice');
    const alice = await f.signIn('alice');
    await expect(
      f.iam.api.roles.listSessions({ token: alice.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.roles.listSessions(
        { token: alice.token },
        { tenantId: f.tenantId, roleId: role.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Other tenants' administrators see nothing of this tenant.
    await expect(
      f.iam.api.roles.listSessions(f.ownerCredential, { tenantId: f.root.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});

describe('RoleSessionSummary client addresses', () => {
  it('shows the issuing address for same-tenant sessions only', async () => {
    const { roleSessionSummary } = await import('../packages/server/src/temporary-credentials.js');
    const base = {
      id: 'ses_1',
      tenantId: 'target',
      identityId: 'usr_1',
      roleId: 'rol_1',
      trustId: 'trs_1',
      kind: 'role',
      tokenHash: 'x',
      createdAt: 1,
      lastSeenAt: 1,
      authenticatedAt: 1,
      expiresAt: 2,
      mfa: false,
      client: { ip: '203.0.113.7' },
    } as unknown as Session;
    expect(roleSessionSummary(base).clientIp).toBe('203.0.113.7');
    expect(roleSessionSummary({ ...base, sourceTenantId: 'target' }).clientIp).toBe('203.0.113.7');
    // A person of another tenant assumed the role: their address stays out of the target tenant's listing.
    const foreign = roleSessionSummary({ ...base, sourceTenantId: 'source' });
    expect(foreign.sourceTenantId).toBe('source');
    expect(foreign).not.toHaveProperty('clientIp');
  });
});

describe("the 'trust-passes-foreign-attributes' finding", () => {
  it('flags legacy cross-tenant trusts, not new ones, and web trusts raise no trust-without-mfa', async () => {
    const f = await organizationFixture();
    const { platform, ops } = await platformOperator(f);
    const role = await readerRole(f);
    const crossTenant = {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
    };
    const legacy = await f.iam.api.trust.create(f.rootCredential, {
      ...crossTenant,
      roleId: role.id,
    });
    await patch(f, 'trusts', legacy.id, { passSourceAttributes: undefined });
    const current = await f.iam.api.trust.create(f.rootCredential, {
      ...crossTenant,
      roleId: role.id,
    });
    const revokedLegacy = await f.iam.api.trust.create(f.rootCredential, {
      ...crossTenant,
      roleId: role.id,
    });
    await patch(f, 'trusts', revokedLegacy.id, { passSourceAttributes: undefined, revoked: true });
    const { trust: sameTenant } = await ownerTrust(f);
    const web = await seedWebTrust(f, role.id, { authorityId: role.authorityId });
    const findings = async () =>
      (await f.iam.api.analysis.findings(f.ownerCredential, { tenantId: f.tenantId })).findings;
    const before = await findings();
    const foreign = before.filter((finding) => finding.kind === 'trust-passes-foreign-attributes');
    expect(foreign).toEqual([
      {
        id: foreign[0]!.id,
        kind: 'trust-passes-foreign-attributes',
        severity: 'medium',
        title: 'A cross-tenant trust passes the source account’s attributes into role sessions',
        detail: expect.stringContaining('trust.update({ passSourceAttributes: false })'),
        subject: { type: 'trust', id: legacy.id },
      },
    ]);
    const withoutMfa = before
      .filter((finding) => finding.kind === 'trust-without-mfa')
      .map((finding) => finding.subject.id);
    expect(withoutMfa).toContain(sameTenant.id);
    expect(withoutMfa).not.toContain(web.id);
    expect(withoutMfa).not.toContain(current.id);
    // Closing the legacy trust clears the finding.
    await f.iam.api.trust.update(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: legacy.id,
      passSourceAttributes: false,
    });
    expect(
      (await findings()).filter((finding) => finding.kind === 'trust-passes-foreign-attributes'),
    ).toEqual([]);
  });
});

describe('roles.assume reads malformed stored trust knobs fail-closed', () => {
  async function tagsAdmitted(
    f: OrganizationFixture,
    trustId: string,
    tags: Record<string, string>,
  ): Promise<boolean> {
    try {
      await f.iam.api.roles.assume(f.ownerCredential, { tenantId: f.tenantId, trustId, tags });
      return true;
    } catch (error) {
      expect(error).toMatchObject({ code: 'ACCESS_DENIED' });
      return false;
    }
  }

  it('admits tags only through a list of strings, and * only as exactly [*]', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    for (const value of ['*', { team: true }, ['team', 7], [['team']], 'team', null]) {
      await patch(f, 'trusts', trust.id, { allowedTagKeys: value });
      expect(await tagsAdmitted(f, trust.id, { team: 'support' })).toBe(false);
    }
    await patch(f, 'trusts', trust.id, { allowedTagKeys: ['*', 'team'] });
    expect(await tagsAdmitted(f, trust.id, { team: 'support' })).toBe(true);
    expect(await tagsAdmitted(f, trust.id, { other: 'x' })).toBe(false);
    await patch(f, 'trusts', trust.id, { allowedTagKeys: ['*'] });
    expect(await tagsAdmitted(f, trust.id, { other: 'x' })).toBe(true);
    // Without tags, a malformed list does not block the assumption itself.
    await patch(f, 'trusts', trust.id, { allowedTagKeys: '*' });
    const plain = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(plain.session.trustId).toBe(trust.id);
  });

  it('treats an unknown source identity mode as forbidden', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    const assume = async (sourceIdentity?: string) =>
      f.iam.api.roles.assume(owner, {
        tenantId: f.tenantId,
        trustId: trust.id,
        ...(sourceIdentity ? { sourceIdentity } : {}),
      });
    for (const mode of ['OPTIONAL', 'Required', 'any', 42, true]) {
      await patch(f, 'trusts', trust.id, { sourceIdentityMode: mode });
      await expect(assume('alice')).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
      expect((await assume()).session.trustId).toBe(trust.id);
    }
    await patch(f, 'trusts', trust.id, { sourceIdentityMode: 'required' });
    await expect(assume()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await assume('alice')).session.sourceIdentity).toBe('alice');
  });

  it('reads passSourceAttributes as a boolean', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const recorded = async (value: unknown) => {
      await patch(f, 'trusts', trust.id, { passSourceAttributes: value });
      const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
        tenantId: f.tenantId,
        trustId: trust.id,
      });
      const event = (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).find(
        (item) =>
          item.action === 'role:assumed' &&
          item.resourceId === role.id &&
          item.sessionContext?.sessionId === assumed.session.id,
      );
      return event?.metadata?.passSourceAttributes;
    };
    expect(await recorded(true)).toBe(true);
    expect(await recorded(undefined)).toBe(true);
    expect(await recorded('false')).toBe(false);
    expect(await recorded('true')).toBe(false);
    expect(await recorded(1)).toBe(false);
    expect(await recorded(false)).toBe(false);
  });
});

describe('issuing clients and bound networks', () => {
  const HOME = '203.0.113.7';
  const AWAY = '198.51.100.9';
  /** A per-request IP from `x-test-ip`, as `http.clientInfo` would derive it behind a trusted proxy. */
  const networkFixture = () =>
    organizationFixture({
      http: {
        clientInfo: (request) => ({
          ip: request.headers.get('x-test-ip') ?? undefined,
          userAgent: 'trust-test',
        }),
      },
    });

  it('roles.assume records the client of a { headers } credential, as sts.getSessionToken does', async () => {
    const f = await networkFixture();
    const { trust } = await ownerTrust(f);
    const input = { tenantId: f.tenantId, trustId: trust.id };
    const owner = await f.ownerSignIn();
    const viaHeaders = await f.iam.api.roles.assume(
      { headers: { authorization: `Bearer ${owner.token}`, 'x-test-ip': AWAY } },
      input,
    );
    expect((await f.iam.store.get<Session>('sessions', viaHeaders.session.id))!.client).toEqual({
      ip: AWAY,
      userAgent: 'trust-test',
    });
    // A token credential with no client scope records none; a scope set by the caller is never replaced.
    const bare = await f.iam.api.roles.assume(owner, input);
    expect((await f.iam.store.get<Session>('sessions', bare.session.id))!.client).toBeUndefined();
    const scoped = await f.iam.auth.withClient({ ip: HOME }, () =>
      f.iam.api.roles.assume(
        { headers: { authorization: `Bearer ${owner.token}`, 'x-test-ip': AWAY } },
        input,
      ),
    );
    expect((await f.iam.store.get<Session>('sessions', scoped.session.id))!.client?.ip).toBe(HOME);
    // The recorded address is judged on every use: an allowlist that excludes it ends the session.
    await f.iam.api.tenants.setAuthPolicy(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'] },
    });
    await expect(
      f.iam.auth.withClient({ ip: HOME }, () => f.iam.authenticate({ token: viaHeaders.token })),
    ).rejects.toMatchObject({ code: 'IP_NOT_ALLOWED' });
  });

  it('records a bound session token presented from another network as auth:session:mismatch', async () => {
    const f = await networkFixture();
    const token = (
      await f.iam.auth.withClient({ ip: HOME, userAgent: 'cli' }, () =>
        f.iam.api.sts.getSessionToken(f.ownerCredential),
      )
    ).token;
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    const mismatches = async () =>
      (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
        (event) => event.action === 'auth:session:mismatch',
      );
    expect((await f.iam.authenticate({ token })).session.kind).toBe('session-token');
    expect(await mismatches()).toEqual([]);
    await expect(
      f.iam.auth.withClient({ ip: AWAY, userAgent: 'curl' }, () => f.iam.authenticate({ token })),
    ).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
      status: 401,
      message: 'This session can only be used from the network it was signed in from',
    });
    const row = (await f.iam.store.find<Session>('sessions', { kind: 'session-token' }))[0]!;
    const [event] = await mismatches();
    expect(event).toMatchObject({
      tenantId: f.tenantId,
      actorId: f.ownerId,
      resourceId: f.ownerId,
      outcome: 'allow',
      metadata: { sessionId: row.id, sessionIp: HOME, ip: AWAY, userAgent: 'curl' },
    });
    // In-process callers passing request headers are judged, and recorded, by the address the headers carry.
    await expect(
      f.iam.authenticate({ headers: { authorization: `Bearer ${token}`, 'x-test-ip': AWAY } }),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    expect(await mismatches()).toHaveLength(2);
    // The refused error carries no stored rows (an in-process caller may log it).
    const error = await f.iam.auth
      .withClient({ ip: AWAY }, () => f.iam.authenticate({ token }))
      .catch((caught: unknown) => caught);
    expect(JSON.stringify(error)).not.toContain(row.tokenHash);
  });
});

describe('deployment ceilings', () => {
  it('bounds maxSessionSeconds by sts.maxRoleSessionSeconds on update too', async () => {
    const sts: BetterIamOptions['sts'] = { maxRoleSessionSeconds: 7200 };
    const f = await organizationFixture({ sts });
    const { trust } = await ownerTrust(f);
    const updated = await f.iam.api.trust.update(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: trust.id,
      maxSessionSeconds: 7200,
    });
    // Raising the cap above the legacy 3600 s default is a loosening: no watermark.
    expect(updated).toMatchObject({ maxSessionSeconds: 7200 });
    expect(updated.sessionsRevokedBefore).toBeUndefined();
    await expect(
      f.iam.api.trust.update(f.rootCredential, {
        tenantId: f.tenantId,
        trustId: trust.id,
        maxSessionSeconds: 7201,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
