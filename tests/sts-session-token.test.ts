import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, PolicyDocument, Session, StoredRecord } from '@better-iam/core';
import type { GetSessionTokenInput, TemporaryCredential } from '@better-iam/server';
import type { ServerContext } from '../packages/server/src/context.js';
import {
  durationWithin,
  roleDurationBounds,
  sessionTokenDurationBounds,
} from '../packages/server/src/temporary-credentials.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * GetSessionToken (`sts.getSessionToken`): the permission, the sources it accepts, duration bounds, scope-down and
 * source policies, the MFA step-up, the per-identity cap, revocation with the source, and the HTTP transport.
 */
const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const ORIGIN = 'http://localhost:3000';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
let names = 0;

/** The TOTP code an authenticator shows at `at` (epoch ms). */
function totp(secret: string, at: number): string {
  const generator = authenticator.clone();
  generator.options = { epoch: at };
  return generator.generate(secret);
}

function allow(actions: string[]): PolicyDocument {
  return { version: 1, statements: [{ effect: 'allow', actions, resources: ['*'] }] };
}

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

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

async function audit(f: OrganizationFixture, tenantId = f.tenantId): Promise<AuditEvent[]> {
  return f.iam.store.find<AuditEvent>('audit', { tenantId });
}

async function allowed(f: OrganizationFixture, token: string, action = 'documents:read') {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'sts-document' },
    })
  ).allowed;
}

function getSessionToken(
  f: OrganizationFixture,
  credential: { token: string },
  input?: GetSessionTokenInput,
): Promise<TemporaryCredential> {
  return f.iam.api.sts.getSessionToken(credential, input);
}

/** Binds a fresh role with `permissions` (an allow over every resource) to an identity of Acme. */
async function grant(f: OrganizationFixture, subjectId: string, permissions: string[]) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Grant ${++names}`,
    permissions,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId,
  });
  return role;
}

/** A service account holding `permissions`, with one API key (optionally scoped or short-lived). */
async function serviceKey(
  f: OrganizationFixture,
  options: { permissions?: string[]; scopes?: string[]; expiresInSeconds?: number } = {},
) {
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `svc-${++names}`,
  });
  if (options.permissions) await grant(f, account.id, options.permissions);
  const key = await f.iam.api.credentials.create(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    identityId: account.id,
    ...(options.scopes ? { scopes: options.scopes } : {}),
    ...(options.expiresInSeconds ? { expiresInSeconds: options.expiresInSeconds } : {}),
  });
  return { account, token: key.token };
}

/** A read-only role in Acme, a same-tenant trust (no MFA) from the owner to it, and an assumed session. */
async function ownerRole(f: OrganizationFixture) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Reader ${++names}`,
    permissions: ['documents:read'],
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

/** Enrolls TOTP for the person signed in with `token`; returns the secret and the new MFA session's token. */
async function enrollTotp(f: OrganizationFixture, token: string) {
  const enrollment = await f.iam.api.auth.beginMfa({ token });
  const confirmed = await f.iam.api.auth.confirmMfa({
    credential: { token },
    code: totp(enrollment.secret, f.now()),
  });
  return { secret: enrollment.secret, token: confirmed.token };
}

function post(
  f: OrganizationFixture,
  path: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<Response> {
  return f.iam.handler(
    new Request(`${ORIGIN}/api/iam/${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
      body: JSON.stringify(body),
    }),
  );
}

describe('sts.getSessionToken', () => {
  it('requires iam:session-tokens:create and returns a typed opaque token once, audited', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const login = await f.signIn('alice');
    await expect(getSessionToken(f, { token: login.token })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      status: 403,
    });
    expect(
      (await audit(f)).filter((event) => event.action === 'iam:session-tokens:create'),
    ).toMatchObject([{ outcome: 'deny', actorId: alice.id, resourceId: alice.id }]);

    await grant(f, alice.id, ['iam:session-tokens:create', 'documents:read']);
    const issued = await getSessionToken(f, { token: login.token }, { sessionName: 'cli-laptop' });
    expect(issued.token).toMatch(/^biam_sts_[A-Za-z0-9_-]{49}$/);
    const source = await rowOf(f, login.token);
    const row = await rowOf(f, issued.token);
    const now = f.now();
    expect(issued).toEqual({
      token: issued.token,
      tokenType: 'Bearer',
      format: 'opaque',
      expiresAt: now + 3600_000,
      expiresIn: 3600,
      session: {
        id: row.id,
        tenantId: f.tenantId,
        kind: 'session-token',
        identityId: alice.id,
        expiresAt: now + 3600_000,
        mfa: false,
        sessionName: 'cli-laptop',
      },
    });
    expect(row).toMatchObject({
      kind: 'session-token',
      tenantId: f.tenantId,
      identityId: alice.id,
      sourceSessionId: source.id,
      tokenHash: sha256(issued.token),
      uniqueKey: sha256(issued.token),
      createdAt: now,
      lastSeenAt: now,
      authenticatedAt: source.authenticatedAt,
      expiresAt: now + 3600_000,
      mfa: false,
      sessionName: 'cli-laptop',
    });
    for (const absent of ['policy', 'sourcePolicy', 'format', 'audience', 'mfaAuthenticatedAt'])
      expect(row).not.toHaveProperty(absent);
    expect(JSON.stringify(issued)).not.toContain(row.tokenHash);

    // The token acts with the identity's grants.
    expect(await allowed(f, issued.token)).toBe(true);
    expect(await allowed(f, issued.token, 'documents:write')).toBe(false);

    const events = await audit(f);
    expect(
      events.filter(
        (event) => event.action === 'iam:session-tokens:create' && event.outcome === 'allow',
      ),
    ).toMatchObject([
      {
        actorId: alice.id,
        resourceId: alice.id,
        sessionContext: { sessionId: source.id, kind: 'user' },
      },
    ]);
    expect(events.filter((event) => event.action === 'session-token:issued')).toMatchObject([
      {
        actorId: alice.id,
        resourceId: alice.id,
        outcome: 'allow',
        metadata: {
          sessionId: row.id,
          sourceSessionKind: 'user',
          durationSeconds: 3600,
          format: 'opaque',
          mfaStepUp: false,
        },
      },
    ]);
  });

  it('mints from user sessions and API keys, and refuses temporary and impersonation sources', async () => {
    const f = await organizationFixture();
    const fromOwner = await getSessionToken(f, f.ownerCredential);
    expect((await f.iam.authenticate({ token: fromOwner.token })).session.kind).toBe(
      'session-token',
    );
    expect(await allowed(f, fromOwner.token, 'documents:write')).toBe(true);

    const key = await serviceKey(f, {
      permissions: ['iam:session-tokens:create', 'documents:read'],
    });
    const fromKey = await getSessionToken(f, { token: key.token });
    const keyRow = await rowOf(f, key.token);
    expect(await rowOf(f, fromKey.token)).toMatchObject({
      identityId: key.account.id,
      sourceSessionId: keyRow.id,
      credentialAuthorityId: keyRow.credentialAuthorityId,
      authenticatedAt: keyRow.authenticatedAt,
      mfa: false,
    });
    expect(await allowed(f, fromKey.token)).toBe(true);
    expect(await allowed(f, fromKey.token, 'documents:write')).toBe(false);

    const chaining = {
      code: 'CREDENTIAL_CHAINING_DISABLED',
      status: 400,
      message: 'Temporary credentials cannot mint session tokens',
    };
    await expect(getSessionToken(f, { token: fromOwner.token })).rejects.toMatchObject(chaining);
    await expect(getSessionToken(f, { token: fromKey.token })).rejects.toMatchObject(chaining);
    const { token: roleToken } = await ownerRole(f);
    await expect(getSessionToken(f, { token: roleToken })).rejects.toMatchObject(chaining);

    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const alice = await f.member('alice');
    const viewAs = await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: alice.id,
      reason: 'ticket 7',
    });
    await expect(getSessionToken(f, { token: viewAs.token })).rejects.toMatchObject({
      code: 'IMPERSONATION_RESTRICTED',
      status: 403,
    });
  });

  it('bounds the duration, refuses malformed input, and never outlives the source', async () => {
    const f = await organizationFixture({ sts: { maxSessionTokenSeconds: 1800 } });
    const get = (input: GetSessionTokenInput) => getSessionToken(f, f.ownerCredential, input);
    expect((await get({})).expiresIn).toBe(1800);
    expect((await get({ durationSeconds: 60 })).expiresIn).toBe(60);
    expect((await get({ durationSeconds: 1800 })).expiresIn).toBe(1800);
    for (const durationSeconds of [59, 1801, 90.5, -1, '900' as never])
      await expect(get({ durationSeconds })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const input of [
      { sessionName: 'x' },
      { sessionName: 'has spaces' },
      { format: 'xml' as never },
      { audience: ['https://api.example'] },
      { policy: 'everything' as never },
    ])
      await expect(get(input)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(get({ format: 'jwt' })).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
      status: 403,
    });

    // An API key that expires sooner caps the token's expiry.
    const key = await serviceKey(f, {
      permissions: ['iam:session-tokens:create'],
      expiresInSeconds: 600,
    });
    const keyRow = await rowOf(f, key.token);
    const capped = await getSessionToken(f, { token: key.token }, { durationSeconds: 1800 });
    expect(capped.expiresAt).toBe(keyRow.expiresAt);
    expect(capped.expiresIn).toBe(600);
    expect((await rowOf(f, capped.token)).expiresAt).toBe(keyRow.expiresAt);
  });

  it('narrows access by the scope-down policy and the source key scopes', async () => {
    const f = await organizationFixture();
    const readOnly = allow(['documents:read']);
    const scoped = await getSessionToken(f, f.ownerCredential, { policy: readOnly });
    expect(await allowed(f, scoped.token)).toBe(true);
    expect(await allowed(f, scoped.token, 'documents:write')).toBe(false);
    expect(await rowOf(f, scoped.token)).toMatchObject({ policy: readOnly });

    const key = await serviceKey(f, {
      permissions: ['iam:session-tokens:create', 'documents:read', 'documents:write'],
      scopes: ['iam:session-tokens:create', 'documents:read'],
    });
    const fromKey = await getSessionToken(f, { token: key.token });
    const keyRow = await rowOf(f, key.token);
    const fromKeyRow = await rowOf(f, fromKey.token);
    expect(fromKeyRow.sourcePolicy).toEqual(keyRow.policy);
    expect(fromKeyRow).not.toHaveProperty('policy');
    expect(await allowed(f, fromKey.token)).toBe(true);
    expect(await allowed(f, fromKey.token, 'documents:write')).toBe(false);
    // Both boundaries apply: the policy allows only writing, the key's scopes only reading.
    const both = await getSessionToken(
      f,
      { token: key.token },
      { policy: allow(['documents:write']) },
    );
    expect(await allowed(f, both.token)).toBe(false);
    expect(await allowed(f, both.token, 'documents:write')).toBe(false);
    // A key whose scopes leave out the permission cannot mint at all.
    const narrow = await serviceKey(f, {
      permissions: ['iam:session-tokens:create', 'documents:read'],
      scopes: ['documents:read'],
    });
    await expect(getSessionToken(f, { token: narrow.token })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });

    // Assertions list the identity's roles, which would escape a scope-down: scoped tokens are refused even when
    // their boundaries allow the action itself.
    await expect(
      f.iam.api.assertions.issue(
        { token: scoped.token },
        { tenantId: f.tenantId, audience: 'billing' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', message: 'Access denied' });
    const assertive = await getSessionToken(f, f.ownerCredential, {
      policy: allow(['documents:read', 'iam:assertions:create']),
    });
    const assertiveKey = await serviceKey(f, {
      permissions: ['iam:session-tokens:create', 'iam:assertions:create'],
      scopes: ['iam:session-tokens:create', 'iam:assertions:create'],
    });
    const fromAssertiveKey = await getSessionToken(f, { token: assertiveKey.token });
    for (const token of [assertive.token, fromAssertiveKey.token])
      await expect(
        f.iam.api.assertions.issue({ token }, { tenantId: f.tenantId, audience: 'billing' }),
      ).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
        message: 'Scoped session tokens cannot obtain assertions',
      });
    const unscoped = await getSessionToken(f, f.ownerCredential);
    const assertion = await f.iam.api.assertions.issue(
      { token: unscoped.token },
      { tenantId: f.tenantId, audience: 'billing' },
    );
    expect(assertion.token.split('.')).toHaveLength(3);
  });

  it('never passes recent-authentication or root checks', async () => {
    const f = await organizationFixture();
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'recent-check',
    });
    const token = await getSessionToken(f, await f.ownerSignIn());
    await expect(
      f.iam.api.credentials.create(
        { token: token.token },
        { tenantId: f.tenantId, identityId: account.id },
      ),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED', status: 403 });
    expect(
      (
        await f.iam.api.credentials.create(await f.ownerSignIn(), {
          tenantId: f.tenantId,
          identityId: account.id,
        })
      ).token,
    ).toMatch(/^biam_key_/);

    // A root administrator's token is neither root nor a root override.
    const platform = f.root.tenant.id;
    expect(
      await f.iam.api.root.listAdministrators(f.rootCredential, { tenantId: platform }),
    ).toHaveLength(1);
    expect(await f.iam.api.roles.list(f.rootCredential, { tenantId: f.tenantId })).not.toHaveLength(
      0,
    );
    const rootToken = await getSessionToken(f, f.rootCredential);
    expect(rootToken.session.mfa).toBe(true);
    await expect(
      f.iam.api.root.listAdministrators({ token: rootToken.token }, { tenantId: platform }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.roles.list({ token: rootToken.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('caps live session tokens per identity', async () => {
    const f = await organizationFixture({ sts: { maxSessionTokensPerIdentity: 2 } });
    await getSessionToken(f, f.ownerCredential);
    await getSessionToken(f, f.ownerCredential, { durationSeconds: 600 });
    await expect(getSessionToken(f, f.ownerCredential)).rejects.toMatchObject({
      code: 'LIMIT_EXCEEDED',
      status: 409,
      message: 'This identity holds the maximum number of live session tokens',
    });
    // The cap is per identity.
    const key = await serviceKey(f, { permissions: ['iam:session-tokens:create'] });
    await getSessionToken(f, { token: key.token });
    // Expired tokens no longer count.
    f.advance(600_000);
    expect((await getSessionToken(f, f.ownerCredential)).token).toMatch(/^biam_sts_/);
    await expect(getSessionToken(f, f.ownerCredential)).rejects.toMatchObject({
      code: 'LIMIT_EXCEEDED',
    });
  });

  it('verifies a first-hand TOTP code for an MFA step-up', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await grant(f, alice.id, ['iam:session-tokens:create', 'documents:read']);
    // Nobody without an authenticator can step up: a person without TOTP, or an API key (refused before counting).
    await expect(
      getSessionToken(f, f.ownerCredential, { mfaCode: '123456' }),
    ).rejects.toMatchObject({ code: 'MFA_NOT_ENROLLED', status: 403 });
    const key = await serviceKey(f, { permissions: ['iam:session-tokens:create'] });
    await expect(
      getSessionToken(f, { token: key.token }, { mfaCode: '123456' }),
    ).rejects.toMatchObject({ code: 'MFA_NOT_ENROLLED', status: 403 });

    const { secret, token } = await enrollTotp(f, (await f.signIn('alice')).token);
    const source = await rowOf(f, token);
    expect(source.mfa).toBe(true);
    // Without a code the source's MFA state is copied.
    const copied = await getSessionToken(f, { token });
    expect(copied.session.mfa).toBe(true);
    expect((await rowOf(f, copied.token)).mfaAuthenticatedAt).toBe(source.mfaAuthenticatedAt);
    // The enrollment code's time step is spent.
    await expect(
      getSessionToken(f, { token }, { mfaCode: totp(secret, f.now()) }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA', status: 401 });

    f.advance(30_000);
    const code = totp(secret, f.now());
    const stepped = await getSessionToken(f, { token }, { mfaCode: code });
    expect(stepped.session.mfa).toBe(true);
    expect(await rowOf(f, stepped.token)).toMatchObject({
      mfa: true,
      mfaAuthenticatedAt: f.now(),
    });
    const events = await audit(f);
    expect(events.some((event) => event.action === 'auth:mfa:step-up')).toBe(true);
    expect(
      events.find(
        (event) =>
          event.action === 'session-token:issued' &&
          (event.metadata as { sessionId?: string } | undefined)?.sessionId === stepped.session.id,
      )?.metadata,
    ).toMatchObject({ mfaStepUp: true });
    // Replayed and wrong codes are refused.
    await expect(getSessionToken(f, { token }, { mfaCode: code })).rejects.toMatchObject({
      code: 'INVALID_MFA',
    });
    await expect(
      getSessionToken(f, { token }, { mfaCode: totp(secret, f.now() + 600_000) }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
  });

  it('counts step-up attempts against the sensitive rate limit before verifying them', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await grant(f, alice.id, ['iam:session-tokens:create']);
    const { secret, token } = await enrollTotp(f, (await f.signIn('alice')).token);
    f.advance(30_000);
    for (let attempt = 0; attempt < 5; attempt++)
      await expect(
        getSessionToken(f, { token }, { mfaCode: totp(secret, f.now() + 600_000) }),
      ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    await expect(
      getSessionToken(f, { token }, { mfaCode: totp(secret, f.now()) }),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    // Tokens without a code are not rate limited.
    expect((await getSessionToken(f, { token })).session.mfa).toBe(true);
  });

  it('lets a stepped-up token assume an MFA-gated trust; the role session ends with the token', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await grant(f, alice.id, ['iam:session-tokens:create', 'iam:roles:assume']);
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Guarded reader',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: alice.id,
      roleId: role.id,
      requireMfa: true,
    });
    const plain = await f.signIn('alice');
    const unverified = await getSessionToken(f, { token: plain.token });
    await expect(
      f.iam.api.roles.assume(
        { token: unverified.token },
        { tenantId: f.tenantId, trustId: trust.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const { secret, token } = await enrollTotp(f, plain.token);
    // Enrolling ended the earlier sessions, and the token minted from one of them.
    await expect(f.iam.authenticate({ token: unverified.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    f.advance(30_000);
    const stepped = await getSessionToken(f, { token }, { mfaCode: totp(secret, f.now()) });
    const assumed = await f.iam.api.roles.assume(
      { token: stepped.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    expect(assumed.session).toMatchObject({ mfa: true, roleId: role.id, trustId: trust.id });
    expect((await rowOf(f, assumed.token)).sourceSessionId).toBe(stepped.session.id);
    expect(await allowed(f, assumed.token)).toBe(true);

    // The person sees the token among their sessions (without hashes) and can revoke it.
    const listed = await f.iam.api.auth.listSessions({ token });
    const entry = listed.find((session) => session.id === stepped.session.id);
    expect(entry).toMatchObject({ kind: 'session-token', current: false });
    expect(entry).not.toHaveProperty('tokenHash');
    expect(entry).not.toHaveProperty('uniqueKey');
    await f.iam.api.auth.revokeSession({ token }, { sessionId: stepped.session.id });
    await expect(f.iam.authenticate({ token: stepped.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(f.iam.authenticate({ token: assumed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Role credential revoked',
    });
  });

  it('answers over HTTP with the token in the body and never sets a cookie', async () => {
    const f = await organizationFixture();
    const bearer = await post(
      f,
      'sts/getSessionToken',
      { sessionName: 'http-cli' },
      { authorization: `Bearer ${f.ownerCredential.token}` },
    );
    expect(bearer.status).toBe(200);
    expect(bearer.headers.get('set-cookie')).toBeNull();
    const body = (await bearer.json()) as { data: TemporaryCredential };
    expect(body.data.token).toMatch(/^biam_sts_/);
    expect(body.data.session).toMatchObject({ kind: 'session-token', sessionName: 'http-cli' });
    expect((await f.iam.authenticate({ token: body.data.token })).session.kind).toBe(
      'session-token',
    );

    const cookie = await post(
      f,
      'sts/getSessionToken',
      {},
      {
        cookie: `better-iam.session=${encodeURIComponent(f.ownerCredential.token)}`,
        origin: ORIGIN,
      },
    );
    expect(cookie.status).toBe(200);
    expect(cookie.headers.get('set-cookie')).toBeNull();
    expect(((await cookie.json()) as { data: TemporaryCredential }).data.token).toMatch(
      /^biam_sts_/,
    );

    const chained = await post(
      f,
      'sts/getSessionToken',
      {},
      { authorization: `Bearer ${body.data.token}` },
    );
    expect(chained.status).toBe(400);
    expect(((await chained.json()) as { error: { code: string } }).error.code).toBe(
      'CREDENTIAL_CHAINING_DISABLED',
    );
  });
});

describe('duration bounds fail closed', () => {
  const context = (sts: Record<string, unknown> = {}) =>
    ({
      config: {
        sts: {
          maxRoleSessionSeconds: 3600,
          maxSessionTokenSeconds: 43200,
          maxSessionTokensPerIdentity: 50,
          ...sts,
        },
      },
    }) as unknown as ServerContext;

  it('treats a malformed stored trust maximum as the 3600 s default, then clamps it', () => {
    const wide = context({ maxRoleSessionSeconds: 43200 });
    for (const malformed of ['forever', '7200', Number.NaN, -5, 0, 1.5, Infinity, null, {}]) {
      const bounds = roleDurationBounds(wide, { maxSessionSeconds: malformed as never }, 'opaque');
      expect(bounds).toEqual({ min: 60, max: 3600, fallback: 900 });
      expect(() => durationWithin(7200, bounds)).toThrow(/durationSeconds/);
      expect(durationWithin(3600, bounds)).toBe(3600);
    }
    expect(roleDurationBounds(wide, { maxSessionSeconds: 7200 }, 'opaque').max).toBe(7200);
    expect(roleDurationBounds(context(), { maxSessionSeconds: 7200 }, 'opaque').max).toBe(3600);
    expect(roleDurationBounds(wide, {}, 'opaque')).toEqual({ min: 60, max: 3600, fallback: 900 });
    expect(roleDurationBounds(wide, { maxSessionSeconds: 600 }, 'opaque')).toEqual({
      min: 60,
      max: 600,
      fallback: 600,
    });
    expect(sessionTokenDurationBounds(context(), 'opaque')).toEqual({
      min: 60,
      max: 43200,
      fallback: 3600,
    });
    expect(sessionTokenDurationBounds(context({ maxSessionTokenSeconds: 'x' }), 'opaque').max).toBe(
      3600,
    );
  });

  it('refuses roles.assume beyond the default when the stored trust value is malformed', async () => {
    const f = await organizationFixture({ sts: { maxRoleSessionSeconds: 43200 } });
    const { trust } = await ownerRole(f);
    await patch<StoredRecord & { maxSessionSeconds?: unknown }>(
      f,
      'trusts',
      trust.id,
      (record) => ({
        ...record,
        maxSessionSeconds: 'forever',
      }),
    );
    const assume = async (durationSeconds: number) =>
      f.iam.api.roles.assume(await f.ownerSignIn(), {
        tenantId: f.tenantId,
        trustId: trust.id,
        durationSeconds,
      });
    await expect(assume(40_000)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(assume(3601)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((await assume(3600)).expiresIn).toBe(3600);
  });
});
