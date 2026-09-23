import { createRequire } from 'node:module';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthenticatedPrincipal, Identity, Session, StoredRecord } from '@better-iam/core';
import {
  credentialTokenKinds,
  credentialTokenScanPattern,
  hashToken,
  newCredentialToken,
  parseCredentialToken,
} from '@better-iam/auth';
import {
  actsInOwnRight,
  nextWatermark,
  revokedByWatermark,
  temporarySessionKinds,
} from '../packages/server/src/session-kinds.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);

afterEach(closeFixtures);

/**
 * Credential plumbing hygiene for authentication sessions: sign-in results never echo the stored token hash, user
 * tokens are prefixed and checksummed (a bad checksum is refused before any storage read, legacy tokens keep
 * working), temporary credentials never pass the recent-authentication check, MFA step-ups verify first-hand TOTP
 * codes once, dedicated attempt budgets apply, and principal.mfaTime's source field is recorded only for first-hand
 * factors.
 */

const DAY = 86_400_000;
const userTokenPattern = /^biam_ses_[A-Za-z0-9_-]{49}$/;

function totp(f: OrganizationFixture, secret: string): string {
  const generator = authenticator.clone();
  generator.options = { epoch: f.now() };
  return generator.generate(secret) as string;
}

/** The error a synchronous call throws, for matching its code. */
function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  return undefined;
}

function expectNoSecretFields(value: unknown): void {
  const text = JSON.stringify(value);
  expect(text).not.toContain('tokenHash');
  expect(text).not.toContain('uniqueKey');
}

async function storedSession(f: OrganizationFixture, token: string): Promise<Session> {
  const rows = await f.iam.store.find<Session>('sessions', { tokenHash: hashToken(token) });
  expect(rows).toHaveLength(1);
  return rows[0]!;
}

/** A member who enrolls an authenticator from their own session; returns the TOTP secret and the confirm result. */
async function enrolledMember(f: OrganizationFixture, name: string) {
  const identity = await f.member(name);
  const first = await f.signIn(name);
  const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
  const confirmed = await f.iam.api.auth.confirmMfa({
    credential: { token: first.token },
    code: totp(f, enrollment.secret),
  });
  return { identity, secret: enrollment.secret, confirmed };
}

describe('sign-in results', () => {
  it('never carry tokenHash or uniqueKey, in process or over HTTP', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const signedIn = await f.signIn('alice');
    expect(signedIn.session.id).toMatch(/^ses_/);
    expectNoSecretFields(signedIn);

    const { secret, confirmed } = await enrolledMember(f, 'bob');
    expect(confirmed.session.mfa).toBe(true);
    expectNoSecretFields(confirmed);

    const challenge = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Bob must require MFA after enrolling');
    f.advance(30_000); // a fresh TOTP step
    const verified = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      code: totp(f, secret),
    });
    expect(verified.session.mfa).toBe(true);
    expectNoSecretFields(verified);

    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/auth/signIn', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
        body: JSON.stringify({
          tenantId: f.tenantId,
          email: 'alice@acme.test',
          password: 'a strong alice password',
        }),
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { session: Record<string, unknown> } };
    expect(body.data.session.identityId).toBeDefined();
    expectNoSecretFields(body);
  });
});

describe('prefixed user tokens', () => {
  it('issues checksummed biam_ses_ tokens that parse', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const { token } = await f.signIn('alice');
    expect(token).toMatch(userTokenPattern);
    expect(token).toHaveLength(58);
    expect(parseCredentialToken(token)).toEqual({ type: 'ses' });
    expect(f.ownerCredential.token).toMatch(userTokenPattern);
    expect(new RegExp(credentialTokenScanPattern).exec(`key=${token};`)?.[0]).toBe(token);
    expect((await f.iam.auth.authenticate({ token })).session.kind).toBe('user');
  });

  it('exposes the token helpers with one kind per type', () => {
    expect(credentialTokenKinds).toEqual({
      ses: 'user',
      key: 'api-key',
      rol: 'role',
      sts: 'session-token',
      dlg: 'delegated',
    });
    for (const type of ['ses', 'key', 'rol', 'sts', 'dlg'] as const) {
      const token = newCredentialToken(type);
      expect(token).toMatch(new RegExp(`^biam_${type}_[A-Za-z0-9_-]{49}$`));
      expect(parseCredentialToken(token)).toEqual({ type });
    }
    const token = newCredentialToken('key');
    for (const value of [
      token.slice(0, -1),
      `${token}A`,
      token.replace('biam_key_', 'biam_xyz_'),
      `biam_ses_${token.slice(9, 52)}`,
      '',
    ])
      expect(parseCredentialToken(value)).toBeUndefined();
  });

  it('refuses a token with a bad checksum before reading storage', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const { token } = await f.signIn('alice');
    const at = token.length - 6;
    const flipped = token.slice(0, at) + (token[at] === 'A' ? 'B' : 'A') + token.slice(at + 1);
    expect(parseCredentialToken(flipped)).toBeUndefined();
    const find = vi.spyOn(f.database, 'find');
    const transaction = vi.spyOn(f.database, 'transaction');
    try {
      const inputs: Parameters<typeof f.iam.auth.authenticate>[0][] = [
        { token: flipped },
        { headers: { authorization: `Bearer ${flipped}` } },
        { headers: { cookie: `better-iam.session=${flipped}` } },
      ];
      for (const input of inputs)
        await expect(f.iam.auth.authenticate(input)).rejects.toMatchObject({
          code: 'UNAUTHENTICATED',
          status: 401,
        });
      expect(find).not.toHaveBeenCalled();
      expect(transaction).not.toHaveBeenCalled();
      // The spies do see storage reads: the genuine token is looked up.
      await f.iam.auth.authenticate({ token });
      expect(find.mock.calls.length + transaction.mock.calls.length).toBeGreaterThan(0);
    } finally {
      find.mockRestore();
      transaction.mockRestore();
    }
  });

  it('keeps legacy unprefixed user tokens working until they expire', async () => {
    const f = await organizationFixture();
    // The shape every token had before prefixes: 43 base64url characters.
    const token = 'legacy_user_token-'.padEnd(43, 'x');
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const now = f.now();
    const row: Session = {
      id: 'ses_legacy_row',
      tenantId: f.tenantId,
      identityId: f.ownerId,
      kind: 'user',
      tokenHash: hashToken(token),
      uniqueKey: hashToken(token),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + DAY,
      authenticatedAt: now,
      mfa: false,
    };
    await f.iam.store.transaction(async (tx) => {
      await tx.insert('sessions', row);
    });
    const principal = await f.iam.auth.authenticate({ token });
    expect(principal.session.id).toBe(row.id);
    expect((await f.iam.authenticate({ token })).identity.id).toBe(f.ownerId);
    f.advance(DAY);
    await expect(f.iam.auth.authenticate({ token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });
});

describe('requireRecent', () => {
  it('refuses temporary credentials and accepts fresh user and API-key sessions', async () => {
    const f = await organizationFixture();
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
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
    const owner = await f.ownerSignIn();
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    const rolePrincipal = await f.iam.authenticate({ token: assumed.token });
    expect(rolePrincipal.session.kind).toBe('role');
    expect(thrown(() => f.iam.auth.requireRecent(rolePrincipal))).toMatchObject({
      code: 'RECENT_AUTH_REQUIRED',
      status: 403,
      message: 'Temporary credentials cannot perform this operation; use a signed-in session',
    });

    const userPrincipal = await f.iam.authenticate(owner);
    expect(() => f.iam.auth.requireRecent(userPrincipal)).not.toThrow();

    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'deployer',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    const keyPrincipal = await f.iam.authenticate({ token: key.token });
    expect(keyPrincipal.session.kind).toBe('api-key');
    expect(() => f.iam.auth.requireRecent(keyPrincipal)).not.toThrow();

    // Session tokens, kinds the service does not know, and any derived session are refused as well.
    const derived: AuthenticatedPrincipal[] = [
      { ...userPrincipal, session: { ...userPrincipal.session, kind: 'session-token' } },
      {
        ...userPrincipal,
        session: { ...userPrincipal.session, kind: 'future-kind' as Session['kind'] },
      },
      { ...userPrincipal, session: { ...userPrincipal.session, sourceSessionId: 'ses_source' } },
    ];
    for (const principal of derived)
      expect(thrown(() => f.iam.auth.requireRecent(principal))).toMatchObject({
        code: 'RECENT_AUTH_REQUIRED',
      });
    // Impersonation keeps its own refusal.
    expect(
      thrown(() =>
        f.iam.auth.requireRecent({
          ...userPrincipal,
          session: { ...userPrincipal.session, kind: 'role', impersonatorId: 'usr_admin' },
        }),
      ),
    ).toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
  });
});

describe('verifyStepUpCode', () => {
  it('accepts a first-hand TOTP code once and refuses wrong codes and missing enrollment', async () => {
    const f = await organizationFixture();
    const { identity, secret } = await enrolledMember(f, 'carol');
    const stepUp = (subject: Identity, code: string) =>
      f.iam.store.transaction(async (tx) => {
        const current = (await tx.get<Identity>('identities', subject.id))!;
        return f.iam.auth.verifyStepUpCode(tx, current, code);
      });
    f.advance(30_000); // past the step the enrollment consumed
    const code = totp(f, secret);
    expect(await stepUp(identity, code)).toEqual({ verifiedAt: f.now() });
    await expect(stepUp(identity, code)).rejects.toMatchObject({
      code: 'INVALID_MFA',
      status: 401,
    });
    f.advance(90_000);
    const valid = totp(f, secret);
    const wrong = String((Number(valid) + 500_000) % 1_000_000).padStart(6, '0');
    await expect(stepUp(identity, wrong)).rejects.toMatchObject({ code: 'INVALID_MFA' });
    await expect(stepUp(identity, 'abcdef')).rejects.toMatchObject({ code: 'INVALID_MFA' });
    const steps = await f.iam.store.find<StoredRecord & { action: string; actorId: string }>(
      'audit',
      {
        tenantId: f.tenantId,
      },
    );
    expect(
      steps.filter((event) => event.action === 'auth:mfa:step-up' && event.actorId === identity.id),
    ).toHaveLength(1);

    // Not enrolled: a person without an authenticator, and any service identity.
    const dave = await f.member('dave');
    await expect(stepUp(dave as Identity, '123456')).rejects.toMatchObject({
      code: 'MFA_NOT_ENROLLED',
      status: 403,
    });
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'robot',
    });
    await expect(stepUp(account as Identity, '123456')).rejects.toMatchObject({
      code: 'MFA_NOT_ENROLLED',
    });

    // The service-kind guard holds even when the store has an enabled authenticator for the service identity: here a
    // copy of Carol's record (it keeps her identityId, so her secret still decrypts and her current code is valid).
    f.advance(30_000);
    const carolRecord = (await f.iam.store.get<StoredRecord>('authMfa', identity.id))!;
    expect(carolRecord.enabled).toBe(true);
    await f.iam.store.transaction(async (tx) => {
      await tx.insert('authMfa', {
        ...carolRecord,
        id: account.id,
        tenantId: account.tenantId,
        lastUsedStep: -1,
      });
    });
    const fresh = totp(f, secret);
    await expect(stepUp(account as Identity, fresh)).rejects.toMatchObject({
      code: 'MFA_NOT_ENROLLED',
      status: 403,
    });
    // The refusal consumed nothing: the planted record is untouched and the code still works for Carol.
    expect((await f.iam.store.get<StoredRecord>('authMfa', account.id))!.lastUsedStep).toBe(-1);
    expect(await stepUp(identity, fresh)).toEqual({ verifiedAt: f.now() });
  });
});

describe('limitAttempt', () => {
  it('applies a dedicated per-subject budget', async () => {
    const f = await organizationFixture();
    await f.iam.auth.limitAttempt(f.tenantId, 'web-identity:trust-1', { limit: 2 });
    await f.iam.auth.limitAttempt(f.tenantId, 'web-identity:trust-1', { limit: 2 });
    const refusal = await f.iam.auth
      .limitAttempt(f.tenantId, 'web-identity:trust-1', { limit: 2 })
      .catch((error: unknown) => error);
    expect(refusal).toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    expect((refusal as { retryAfterMs?: number }).retryAfterMs).toBeGreaterThan(0);
    // Other subjects keep their own budget, and the tiered form still works.
    await f.iam.auth.limitAttempt(f.tenantId, 'web-identity:trust-2', { limit: 2 });
    await f.iam.auth.limitAttempt(f.tenantId, 'step-up:someone', { tier: 'sensitive' });
  });

  it("ignores the tenant's maxAttempts when a dedicated limit is given", async () => {
    const f = await organizationFixture();
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { maxAttempts: 1 },
    });
    // The tenant cap does tighten the tiered form: one attempt, then refused.
    await f.iam.auth.limitAttempt(f.tenantId, 'sign-in:capped');
    await expect(f.iam.auth.limitAttempt(f.tenantId, 'sign-in:capped')).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // A dedicated budget above both the tenant cap (1) and the deployment default (10) is honoured in full...
    for (let attempt = 0; attempt < 12; attempt++)
      await f.iam.auth.limitAttempt(f.tenantId, 'web-identity:busy', { limit: 12 });
    await expect(
      f.iam.auth.limitAttempt(f.tenantId, 'web-identity:busy', { limit: 12 }),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    // ...and a dedicated budget is never loosened by a generous tenant cap either.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { maxAttempts: 100 },
    });
    await f.iam.auth.limitAttempt(f.tenantId, 'web-identity:strict', { limit: 1 });
    await expect(
      f.iam.auth.limitAttempt(f.tenantId, 'web-identity:strict', { limit: 1 }),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  });
});

describe('mfaAuthenticatedAt', () => {
  it('is recorded for first-hand factors only', async () => {
    const f = await organizationFixture();
    const root = await storedSession(f, f.rootCredential.token);
    expect(root.mfa).toBe(true);
    expect(root.mfaAuthenticatedAt).toBe(root.createdAt);

    // A password-only session has no MFA time.
    await f.member('alice');
    const password = await storedSession(f, (await f.signIn('alice')).token);
    expect(password.mfaAuthenticatedAt).toBeUndefined();

    // A verified code records it; a remembered device satisfies MFA without recording it.
    const { secret } = await enrolledMember(f, 'bob');
    const challenge = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Bob must require MFA after enrolling');
    f.advance(30_000);
    const verified = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      code: totp(f, secret),
      rememberDevice: true,
    });
    expect(verified.deviceToken).toBeDefined();
    expect((await storedSession(f, verified.token)).mfaAuthenticatedAt).toBe(f.now());
    f.advance(60_000);
    const remembered = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
      deviceToken: verified.deviceToken!,
    });
    if (!('token' in remembered)) throw new Error('The device token should skip MFA');
    const deviceRow = await storedSession(f, remembered.token);
    expect(deviceRow.mfa).toBe(true);
    expect(deviceRow.trustedDeviceId).toBeDefined();
    expect(deviceRow.mfaAuthenticatedAt).toBeUndefined();

    // Impersonation inherits the actor's MFA flag, never a factor time.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const viewAs = await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: password.identityId,
      reason: 'ticket 42',
    });
    expect(viewAs.token).toMatch(userTokenPattern);
    const impersonation = await storedSession(f, viewAs.token);
    expect(impersonation.impersonatorId).toBe(f.ownerId);
    expect(impersonation.mfaAuthenticatedAt).toBeUndefined();
    expectNoSecretFields(viewAs.session);
  });
});

describe('session kinds', () => {
  it('classifies kinds and computes revocation watermarks', () => {
    expect([...temporarySessionKinds].sort()).toEqual(['delegated', 'role', 'session-token']);
    expect(actsInOwnRight({ kind: 'user' })).toBe(true);
    expect(actsInOwnRight({ kind: 'api-key' })).toBe(true);
    expect(actsInOwnRight({ kind: 'role' })).toBe(false);
    expect(actsInOwnRight({ kind: 'session-token' })).toBe(false);
    expect(actsInOwnRight({ kind: 'future-kind' as Session['kind'] })).toBe(false);

    expect(revokedByWatermark(100)).toBe(false);
    expect(revokedByWatermark(100, undefined, 100)).toBe(false);
    expect(revokedByWatermark(99, undefined, 100)).toBe(true);
    expect(revokedByWatermark(150, 100, 200)).toBe(true);

    const now = 1_000;
    expect(nextWatermark(undefined, undefined, now)).toBe(now + 1);
    expect(nextWatermark(500, 200, now)).toBe(500);
    expect(nextWatermark(500, 800, now)).toBe(800);
    expect(nextWatermark(undefined, now + 1, now)).toBe(now + 1);
    for (const before of [now + 2, -1, 1.5, '10', Number.NaN, Number.MAX_SAFE_INTEGER + 2])
      expect(thrown(() => nextWatermark(undefined, before, now))).toMatchObject({
        code: 'INVALID_INPUT',
        message: 'before must be a time no later than now',
      });
  });
});
