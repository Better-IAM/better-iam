import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument, PolicyStatement, Session, StoredRecord } from '@better-iam/core';
import { sameHash } from '../packages/server/src/utils.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Hardening of temporary credentials after the Wave 3 review: trust flags read fail-closed (`passSourceAttributes` in
 * decisions, `requireMfa` at assumption and on every use), a constant-time hash comparison helper, session tokens
 * recording the client of in-process `{ headers }` callers, dead tokens neither holding places under the per-identity
 * cap nor staying stored, `bindSessionsToIp` applying to session tokens, session tokens and impersonations refused by
 * certification decisions, and derived credentials refused by package request withdrawals.
 */
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const HOME = '203.0.113.7';
const AWAY = '198.51.100.9';

/** Acme with a `department` attribute, a controllable per-request IP (`x-test-ip`), and an optional token cap. */
function hardeningFixture(maxSessionTokensPerIdentity?: number) {
  return organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { department: 'string' },
    },
    http: {
      clientInfo: (request) => ({
        ip: request.headers.get('x-test-ip') ?? undefined,
        userAgent: 'hardening-test',
      }),
    },
    ...(maxSessionTokensPerIdentity ? { sts: { maxSessionTokensPerIdentity } } : {}),
  });
}

function allow(actions: string[], conditions?: PolicyStatement['conditions']): PolicyStatement {
  return { effect: 'allow', actions, resources: ['*'], ...(conditions ? { conditions } : {}) };
}
function policyDocument(...statements: PolicyStatement[]): PolicyDocument {
  return { version: 1, statements };
}

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

/** Rewrites a stored record; `undefined` values remove the field (a legacy shape). */
async function patch(
  f: OrganizationFixture,
  collection: string,
  id: string,
  change: Record<string, unknown>,
) {
  await f.iam.store.transaction(async (tx) => {
    const record = { ...(await tx.get<StoredRecord>(collection, id))! } as Record<string, unknown>;
    for (const [key, value] of Object.entries(change))
      if (value === undefined) delete record[key];
      else record[key] = value;
    await tx.put(collection, record as StoredRecord);
  });
}

async function allowed(f: OrganizationFixture, token: string, action: string): Promise<boolean> {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'hardening-document' },
    })
  ).allowed;
}

/** A role in Acme and a same-tenant trust (no MFA) from the owner to it. */
async function ownerTrust(f: OrganizationFixture, document: PolicyDocument, name = 'Hardening') {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name,
    document,
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  return { role, trust };
}

const from = <T>(f: OrganizationFixture, ip: string, fn: () => Promise<T>) =>
  f.iam.auth.withClient({ ip, userAgent: 'hardening-test' }, fn);

describe('trust flags read fail-closed', () => {
  it('passes source attributes into role decisions only for true or a legacy trust', async () => {
    const f = await hardeningFixture();
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: f.ownerId,
      attributes: { department: 'eng' },
    });
    const { trust } = await ownerTrust(
      f,
      policyDocument(
        allow(['documents:read'], { StringEquals: { 'principal.department': 'eng' } }),
      ),
    );
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    // Same-tenant trusts pass attributes by default.
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    // Malformed values never pass them, whatever their truthiness.
    for (const value of ['false', 'true', 0, 1, null, {}]) {
      await patch(f, 'trusts', trust.id, { passSourceAttributes: value });
      expect(await allowed(f, assumed.token, 'documents:read'), JSON.stringify(value)).toBe(false);
    }
    await patch(f, 'trusts', trust.id, { passSourceAttributes: false });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(false);
    await patch(f, 'trusts', trust.id, { passSourceAttributes: true });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
    // A legacy trust without the field passes them.
    await patch(f, 'trusts', trust.id, { passSourceAttributes: undefined });
    expect(await allowed(f, assumed.token, 'documents:read')).toBe(true);
  });

  it('requires MFA unless the stored flag is exactly false, at assumption and on every use', async () => {
    const f = await hardeningFixture();
    const { trust } = await ownerTrust(f, policyDocument(allow(['documents:read'])));
    const assume = async () =>
      f.iam.api.roles.assume(await f.ownerSignIn(), { tenantId: f.tenantId, trustId: trust.id });
    const assumed = await assume();
    expect((await f.iam.authenticate({ token: assumed.token })).session.kind).toBe('role');
    // `trust.create` stores a boolean (default true); a missing field means that default, anything malformed
    // requires MFA too. The owner's sessions carry no MFA, so each is refused.
    for (const value of [undefined, 'false', 0, null, '', true]) {
      await patch(f, 'trusts', trust.id, { requireMfa: value });
      await expect(assume(), `assume ${JSON.stringify(value)}`).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
        message: 'Role trust does not permit assumption',
      });
      await expect(
        f.iam.authenticate({ token: assumed.token }),
        `use ${JSON.stringify(value)}`,
      ).rejects.toMatchObject({ code: 'UNAUTHENTICATED', message: 'Role credential revoked' });
    }
    // Only the boolean false waives it; the existing role session works again.
    await patch(f, 'trusts', trust.id, { requireMfa: false });
    expect((await f.iam.authenticate({ token: assumed.token })).session.kind).toBe('role');
    expect((await assume()).token).toBeTruthy();
  });
});

describe('sameHash', () => {
  it('compares in constant time and never matches malformed or differently sized values', () => {
    const a = sha256('one');
    expect(sameHash(a, sha256('one'))).toBe(true);
    expect(sameHash(a, sha256('two'))).toBe(false);
    expect(sameHash(a, a.slice(1))).toBe(false);
    expect(sameHash('', '')).toBe(true);
    // Equal string lengths but different byte lengths are refused rather than thrown.
    expect(sameHash('é', 'e')).toBe(false);
    expect(sameHash(undefined as never, a)).toBe(false);
    expect(sameHash(a, 42 as never)).toBe(false);
  });
});

describe('sts.getSessionToken hardening', () => {
  it('records the issuing client of an in-process { headers } caller', async () => {
    const f = await hardeningFixture();
    const viaHeaders = await f.iam.api.sts.getSessionToken({
      headers: { authorization: `Bearer ${f.ownerCredential.token}`, 'x-test-ip': AWAY },
    });
    expect((await rowOf(f, viaHeaders.token)).client).toEqual({
      ip: AWAY,
      userAgent: 'hardening-test',
    });
    // A token credential with no client scope records none; a scope set by the caller is never replaced.
    const bare = await f.iam.api.sts.getSessionToken(f.ownerCredential);
    expect((await rowOf(f, bare.token)).client).toBeUndefined();
    const scoped = await from(f, HOME, () =>
      f.iam.api.sts.getSessionToken({
        headers: { authorization: `Bearer ${f.ownerCredential.token}`, 'x-test-ip': AWAY },
      }),
    );
    expect((await rowOf(f, scoped.token)).client?.ip).toBe(HOME);
    // The recorded address is judged against the tenant's allowlist on every use.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'] },
    });
    await expect(f.iam.authenticate({ token: viaHeaders.token })).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
    });
    expect((await f.iam.authenticate({ token: scoped.token })).session.kind).toBe('session-token');
    expect((await f.iam.authenticate({ token: bare.token })).session.kind).toBe('session-token');
  });

  it('does not count tokens whose source session is gone against the cap', async () => {
    const f = await hardeningFixture(2);
    const first = await f.ownerSignIn();
    await f.iam.api.sts.getSessionToken(first);
    await f.iam.api.sts.getSessionToken(first, { durationSeconds: 900 });
    const second = await f.ownerSignIn();
    await expect(f.iam.api.sts.getSessionToken(second)).rejects.toMatchObject({
      code: 'LIMIT_EXCEEDED',
      status: 409,
      message: 'This identity holds the maximum number of live session tokens',
    });
    // Signing out removes the source row; its tokens are dead and no longer hold places.
    await f.iam.api.auth.signOut(first);
    const fresh = await f.iam.api.sts.getSessionToken(second);
    expect(fresh.token).toMatch(/^biam_sts_/);
    await f.iam.api.sts.getSessionToken(second);
    // Live tokens still count.
    await expect(f.iam.api.sts.getSessionToken(second)).rejects.toMatchObject({
      code: 'LIMIT_EXCEEDED',
    });
  });

  const storedTokens = async (f: OrganizationFixture) =>
    (await f.iam.store.find<Session>('sessions', { identityId: f.ownerId, kind: 'session-token' }))
      .length;

  it('deletes dead tokens at issuance, so sign-in, mint, sign-out rounds never grow storage past the cap', async () => {
    const cap = 3;
    const f = await organizationFixture({ sts: { maxSessionTokensPerIdentity: cap } });
    for (let round = 0; round < 3; round++) {
      const source = await f.ownerSignIn();
      for (let minted = 0; minted < cap; minted++)
        await f.iam.api.sts.getSessionToken(source, { durationSeconds: 43200 });
      await expect(f.iam.api.sts.getSessionToken(source)).rejects.toMatchObject({
        code: 'LIMIT_EXCEEDED',
      });
      expect(await storedTokens(f), `round ${round}`).toBe(cap);
      await f.iam.api.auth.signOut(source);
    }
    // The next issuance removes the last round's dead rows as well.
    await f.iam.api.sts.getSessionToken(await f.ownerSignIn());
    expect(await storedTokens(f)).toBe(1);
  });

  it('frees and deletes the places of tokens whose source session idled out', async () => {
    const f = await organizationFixture({
      sts: { maxSessionTokensPerIdentity: 2 },
      authentication: { sessionIdleTimeoutMs: 60 * 60_000 },
    });
    const idle = await f.ownerSignIn();
    await f.iam.api.sts.getSessionToken(idle, { durationSeconds: 43200 });
    await f.iam.api.sts.getSessionToken(idle, { durationSeconds: 43200 });
    f.advance(50 * 60_000);
    const active = await f.ownerSignIn();
    // Fifty idle minutes: the source still works, so its tokens hold their places.
    await expect(f.iam.api.sts.getSessionToken(active)).rejects.toMatchObject({
      code: 'LIMIT_EXCEEDED',
    });
    f.advance(20 * 60_000);
    // Seventy: the source idled out and can never be used again, nor can its unexpired tokens, although its row is
    // still stored.
    const idleRow = await rowOf(f, idle.token);
    const fresh = await f.iam.api.sts.getSessionToken(active);
    expect(await f.iam.store.get<Session>('sessions', idleRow.id)).toBeDefined();
    await expect(f.iam.api.auth.getSession(idle)).rejects.toMatchObject({ status: 401 });
    expect(fresh.token).toMatch(/^biam_sts_/);
    expect(await storedTokens(f)).toBe(1);
  });
});

describe('session tokens and bindSessionsToIp', () => {
  it('refuses a bound token from another address, like a user session', async () => {
    const f = await hardeningFixture();
    const token = (await from(f, HOME, () => f.iam.api.sts.getSessionToken(f.ownerCredential)))
      .token;
    const bare = (await f.iam.api.sts.getSessionToken(f.ownerCredential)).token;
    const use = (ip: string | undefined, value: string) =>
      ip
        ? from(f, ip, () => f.iam.authenticate({ token: value }))
        : f.iam.authenticate({ token: value });
    // Off by default: the token roams.
    expect((await use(AWAY, token)).session.kind).toBe('session-token');
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    expect((await use(HOME, token)).session.kind).toBe('session-token');
    await expect(use(AWAY, token)).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
      status: 401,
      message: 'This session can only be used from the network it was signed in from',
    });
    // In-process callers passing request headers are judged by the address those headers carry.
    await expect(
      f.iam.authenticate({ headers: { authorization: `Bearer ${token}`, 'x-test-ip': AWAY } }),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    // Unknown addresses on either side are not judged.
    expect((await use(undefined, token)).session.kind).toBe('session-token');
    expect((await use(AWAY, bare)).session.kind).toBe('session-token');
    // Every decision path authenticates the same way.
    await expect(
      from(f, AWAY, () =>
        f.iam.authorize({
          token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'hardening-document' },
        }),
      ),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
  });
});

describe('derived credentials in reviews and package requests', () => {
  /** A named-reviewer campaign over Alice's Readers binding, a session token and a role session of the owner. */
  async function scenario() {
    const f = await hardeningFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const campaign = await api.certifications.create(owner, {
      tenantId,
      name: 'Quarterly review',
      roleIds: [readers.id],
    });
    const [item] = (await api.certifications.get(owner, { tenantId, campaignId: campaign.id }))
      .items;
    if (!item) throw new Error('The campaign must hold an item');
    const pkg = await api.packages.create(owner, {
      tenantId,
      name: 'Readers kit',
      roleIds: [readers.id],
      requestable: true,
    });
    const { trust } = await ownerTrust(f, policyDocument(allow(['*'])), 'Everything');
    const role = {
      token: (await api.roles.assume(await f.ownerSignIn(), { tenantId, trustId: trust.id })).token,
    };
    const sts = { token: (await api.sts.getSessionToken(await f.ownerSignIn())).token };
    return { f, api, tenantId, owner, campaign, item, pkg, role, sts };
  }

  it('refuses certification decisions from a session token or an impersonation, not a role session', async () => {
    const s = await scenario();
    const decide = (credential: { token: string }, decision: 'keep' | 'revoke' = 'revoke') =>
      s.api.certifications.decide(credential, {
        tenantId: s.tenantId,
        campaignId: s.campaign.id,
        decisions: [{ itemId: s.item.id, decision }],
      });
    const stored = async () =>
      (
        await s.f.iam.store.find<StoredRecord & { decision?: string }>('certificationItems', {
          tenantId: s.tenantId,
        })
      )[0]?.decision;
    await expect(decide(s.sts)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      status: 403,
      message: 'Reviews are made from an ordinary session of the campaign tenant',
    });
    // An administrator viewing as a reviewer never records a decision in the reviewer's name.
    await s.api.tenants.setAuthPolicy(s.owner, {
      tenantId: s.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const reviewers = await s.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Reviewers',
      permissions: ['iam:certifications:read', 'iam:certifications:review'],
    });
    const bob = await s.f.member('bob');
    await s.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: reviewers.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const viewAs = await s.api.identities.impersonate(await s.f.ownerSignIn(), {
      tenantId: s.tenantId,
      identityId: bob.id,
      reason: 'ticket 7',
    });
    await expect(decide({ token: viewAs.token })).rejects.toMatchObject({
      code: 'IMPERSONATION_RESTRICTED',
      status: 403,
    });
    expect(await stored()).toBeUndefined();
    // An assumed role holding iam:certifications:review decides, as it always could.
    expect(await decide(s.role, 'keep')).toEqual({ recorded: 1 });
    expect(await stored()).toBe('keep');
    // So do the reviewer's own session and a user session of the owner.
    expect(await decide(await s.f.signIn('bob'))).toEqual({ recorded: 1 });
    expect(await decide(await s.f.ownerSignIn())).toEqual({ recorded: 1 });
    expect(await stored()).toBe('revoke');
  });

  it('refuses withdrawing a package request from a derived credential but still lists it', async () => {
    const s = await scenario();
    const user = await s.f.ownerSignIn();
    const request = await s.api.packages.request(user, {
      tenantId: s.tenantId,
      packageId: s.pkg.id,
    });
    expect(request.status).toBe('pending');
    const cancel = (credential: { token: string }) =>
      s.api.packages.cancelRequest(credential, { tenantId: s.tenantId, requestId: request.id });
    for (const [name, credential] of [
      ['session token', s.sts],
      ['role session', s.role],
    ] as const)
      await expect(cancel(credential), name).rejects.toMatchObject({
        code: 'INVALID_INPUT',
        message: 'Requests are made from an ordinary session of the target tenant',
      });
    // The read-only self-service view stays open to a session token.
    const mine = await s.api.packages.listMine(s.sts, { tenantId: s.tenantId });
    expect(mine.requests.map((listed) => listed.id)).toEqual([request.id]);
    expect(mine.requests[0]).toMatchObject({ packageId: s.pkg.id, status: 'pending' });
    expect(mine.packages.find((pkg) => pkg.id === s.pkg.id)?.pending?.id).toBe(request.id);
    expect((await cancel(user)).status).toBe('cancelled');
  });
});
