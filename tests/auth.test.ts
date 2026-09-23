import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import {
  createAuth,
  encryptSecret,
  decryptSecret,
  type AuthService,
  type DeliveryMessage,
  type SignInResult,
  type SessionResult,
} from '@better-iam/auth';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Identity, Tenant } from '@better-iam/core';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../packages/auth/package.json', import.meta.url));
const { authenticator } =
  require('otplib') as typeof import('../packages/auth/node_modules/otplib');
const SECRET = 'test-secret-32-characters-minimum-better-iam';
const PASSWORD = 'test-password-long-enough';
let store: IamStore;
let auth: AuthService;
let now: number;
let messages: DeliveryMessage[];

async function identity(
  tenantId = 'org',
  extra: { rootAdmin?: boolean; email?: string } = {},
): Promise<Identity> {
  return store.transaction((tx) =>
    auth.createIdentity(tx, {
      tenantId,
      email: extra.email ?? 'same@example.com',
      name: 'Test User',
      password: PASSWORD,
      emailVerified: true,
      rootAdmin: extra.rootAdmin,
    }),
  );
}
function session(result: SignInResult): SessionResult {
  if ('mfaRequired' in result) throw new Error('Unexpected MFA challenge');
  return result;
}
function totp(secret: string): string {
  const generator = authenticator.clone();
  generator.options = { epoch: now };
  return generator.generate(secret);
}

beforeEach(async () => {
  now = Date.now();
  messages = [];
  store = sqliteAdapter({ filename: ':memory:' });
  await store.migrate();
  auth = createAuth({
    store,
    secret: SECRET,
    baseURL: 'https://iam.example.com',
    signUpEnabled: true,
    sendEmail: async (message) => {
      messages.push(message);
    },
    sendSms: async (message) => {
      messages.push(message);
    },
    passwordlessEmail: true,
    passwordlessSms: true,
    passkeys: { rpID: 'iam.example.com' },
    now: () => now,
  });
  await store.transaction(async (tx) => {
    for (const [id, parentId, type] of [
      ['root', null, 'root'],
      ['org', 'root', 'organization'],
      ['sibling', 'root', 'organization'],
      ['project', 'org', 'project'],
    ] as const)
      await tx.insert<Tenant>('tenants', {
        id,
        tenantId: id,
        name: id,
        parentId,
        type,
        status: 'active',
        createdAt: now,
      });
  });
});
afterEach(async () => {
  await store.close();
});

describe('tenant authentication and session revocation', () => {
  it('keeps identical email addresses separate across tenants and rejects forged tenant headers', async () => {
    const first = await identity('org');
    const second = await identity('sibling');
    const login = session(
      await auth.signIn({ tenantId: 'org', email: 'SAME@example.com', password: PASSWORD }),
    );
    const principal = await auth.authenticate({
      token: login.token,
      headers: { 'x-tenant-id': 'sibling' },
    });
    expect(principal.identity.id).toBe(first.id);
    expect(principal.identity.id).not.toBe(second.id);
    expect(principal.identity.tenantId).toBe('org');
    expect((await auth.getSession({ token: login.token })).identity).not.toHaveProperty(
      'passwordHash',
    );
    expect((await auth.listSessions({ token: login.token }))[0]).not.toHaveProperty('tokenHash');
    expect((await store.get<Identity>('identities', first.id))!.passwordHash).toMatch(
      /^\$argon2id\$/,
    );
  });

  it('checks current ancestor status and session expiry on each use', async () => {
    await identity('project');
    const login = session(
      await auth.signIn({ tenantId: 'project', email: 'same@example.com', password: PASSWORD }),
    );
    await store.transaction(async (tx) => {
      const parent = (await tx.get<Tenant>('tenants', 'org'))!;
      parent.status = 'suspended';
      await tx.put('tenants', parent);
    });
    await expect(auth.authenticate({ token: login.token })).rejects.toMatchObject({
      code: 'TENANT_UNAVAILABLE',
    });
    await store.transaction(async (tx) => {
      const parent = (await tx.get<Tenant>('tenants', 'org'))!;
      parent.status = 'active';
      await tx.put('tenants', parent);
    });
    now += 8 * 24 * 60 * 60_000;
    await expect(auth.authenticate({ token: login.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('uses host-prefixed HTTPS cookies and applies the same idle checks to persisted protocol session IDs', async () => {
    await identity();
    const login = session(
      await auth.signIn({ tenantId: 'org', email: 'same@example.com', password: PASSWORD }),
    );
    await expect(
      auth.authenticate({ headers: { cookie: `better-iam.session=${login.token}` } }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(
      (await auth.authenticate({ headers: { cookie: `__Host-better-iam.session=${login.token}` } }))
        .session.id,
    ).toBe(login.session.id);
    now += 23 * 60 * 60_000;
    expect((await auth.validateSessionId(login.session.id)).session.lastSeenAt).toBe(now);
    now += 24 * 60 * 60_000;
    await expect(auth.validateSessionId(login.session.id)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(auth.authenticate({ token: login.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('persists failed-login rate limits outside failed transactions', async () => {
    for (let i = 0; i < 10; i++)
      await expect(
        auth.signIn({ tenantId: 'org', email: 'unknown@example.com', password: PASSWORD }),
      ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(
      auth.signIn({ tenantId: 'org', email: 'unknown@example.com', password: PASSWORD }),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    now += 16 * 60_000;
    await expect(
      auth.signIn({ tenantId: 'org', email: 'unknown@example.com', password: PASSWORD }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('requires verified email by default for signup and consumes verification once', async () => {
    const result = await auth.signUp({
      tenantId: 'org',
      email: 'new@example.com',
      name: 'New',
      password: PASSWORD,
    });
    expect(result.verificationRequired).toBe(true);
    expect(result.identity).not.toHaveProperty('passwordHash');
    await expect(
      auth.signIn({ tenantId: 'org', email: 'new@example.com', password: PASSWORD }),
    ).rejects.toMatchObject({ code: 'EMAIL_UNVERIFIED' });
    const stored = JSON.stringify(await store.find('outbox'));
    expect(stored).not.toContain('"token":');
    expect(await auth.dispatchOutbox()).toEqual({ delivered: 1, failed: 0, abandoned: 0 });
    const token = messages[0]!.payload.token!;
    await expect(auth.verifyEmail({ tenantId: 'sibling', token })).rejects.toMatchObject({
      code: 'INVALID_CHALLENGE',
    });
    const attempts = await Promise.allSettled([
      auth.verifyEmail({ tenantId: 'org', token }),
      auth.verifyEmail({ tenantId: 'org', token }),
    ]);
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(
      session(await auth.signIn({ tenantId: 'org', email: 'new@example.com', password: PASSWORD }))
        .token,
    ).toBeTruthy();
    expect((await store.find('outbox'))[0]!.payload).toEqual({});
    await expect(
      auth.signUp({ tenantId: 'root', email: 'bad@example.com', name: 'Bad', password: PASSWORD }),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('revokes sessions immediately after password changes and enforces recent authentication', async () => {
    await identity();
    const login = session(
      await auth.signIn({ tenantId: 'org', email: 'same@example.com', password: PASSWORD }),
    );
    now += 6 * 60_000;
    await expect(
      auth.changePassword(
        { token: login.token },
        { currentPassword: PASSWORD, password: 'replacement-password' },
      ),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = session(
      await auth.reauthenticate({ token: login.token }, { password: PASSWORD }),
    );
    await auth.changePassword(
      { token: fresh.token },
      { currentPassword: PASSWORD, password: 'replacement-password' },
    );
    await expect(auth.authenticate({ token: login.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(auth.authenticate({ token: fresh.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(
      session(
        await auth.signIn({
          tenantId: 'org',
          email: 'same@example.com',
          password: 'replacement-password',
        }),
      ).token,
    ).toBeTruthy();
  });
});

describe('MFA enrollment, challenges, and account recovery', () => {
  it('allows root MFA enrollment from a restricted challenge, rejects replay, and keeps MFA after password recovery', async () => {
    const root = await identity('root', { rootAdmin: true });
    const login = await auth.signIn({
      tenantId: 'root',
      email: 'same@example.com',
      password: PASSWORD,
    });
    expect(login).toMatchObject({ mfaRequired: true, enrollmentRequired: true });
    if (!('mfaRequired' in login)) throw new Error('Expected MFA');
    await expect(auth.authenticate({ token: login.challenge })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    const credential = { tenantId: 'root', challenge: login.challenge };
    const enrollment = await auth.beginMfa(credential);
    expect(JSON.stringify(await store.get('authMfa', root.id))).not.toContain(enrollment.secret);
    const verified = await auth.confirmMfa({ credential, code: totp(enrollment.secret) });
    expect(verified.recoveryCodes).toHaveLength(10);
    expect((await auth.authenticate({ token: verified.token })).session.mfa).toBe(true);
    const nextLogin = await auth.signIn({
      tenantId: 'root',
      email: 'same@example.com',
      password: PASSWORD,
    });
    if (!('mfaRequired' in nextLogin)) throw new Error('Expected MFA');
    await expect(
      auth.beginMfa({ tenantId: 'root', challenge: nextLogin.challenge }),
    ).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    await expect(
      auth.verifyMfa({
        tenantId: 'root',
        challenge: nextLogin.challenge,
        code: totp(enrollment.secret),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    now += 30_000;
    await auth.verifyMfa({
      tenantId: 'root',
      challenge: nextLogin.challenge,
      code: totp(enrollment.secret),
    });
    await expect(
      auth.verifyMfa({
        tenantId: 'root',
        challenge: nextLogin.challenge,
        code: totp(enrollment.secret),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    await auth.requestPasswordReset({ tenantId: 'root', email: 'same@example.com' });
    await auth.dispatchOutbox();
    const resetToken = messages.find((message) => message.template === 'password-reset')!.payload
      .token!;
    await auth.resetPassword({
      tenantId: 'root',
      token: resetToken,
      password: 'replacement-password',
    });
    await expect(auth.authenticate({ token: verified.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    const afterReset = await auth.signIn({
      tenantId: 'root',
      email: 'same@example.com',
      password: 'replacement-password',
    });
    expect(afterReset).toMatchObject({ mfaRequired: true, enrollmentRequired: false });
  });

  it('accepts each MFA recovery code only once, even across simultaneous login challenges', async () => {
    await identity();
    const login = session(
      await auth.signIn({ tenantId: 'org', email: 'same@example.com', password: PASSWORD }),
    );
    const enrollment = await auth.beginMfa({ token: login.token });
    const enabled = await auth.confirmMfa({
      credential: { token: login.token },
      code: totp(enrollment.secret),
    });
    const challenge1 = await auth.signIn({
      tenantId: 'org',
      email: 'same@example.com',
      password: PASSWORD,
    });
    const challenge2 = await auth.signIn({
      tenantId: 'org',
      email: 'same@example.com',
      password: PASSWORD,
    });
    if (!('mfaRequired' in challenge1) || !('mfaRequired' in challenge2))
      throw new Error('Expected MFA');
    const attempts = await Promise.allSettled(
      [challenge1, challenge2].map((challenge) =>
        auth.recoverMfa({
          tenantId: 'org',
          challenge: challenge.challenge,
          code: enabled.recoveryCodes[0]!,
        }),
      ),
    );
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(JSON.stringify(await store.find('authMfa'))).not.toContain(enabled.recoveryCodes[0]);
  });

  it('rotates recovery codes atomically and prohibits disabling root MFA', async () => {
    await identity('root', { rootAdmin: true });
    const login = await auth.signIn({
      tenantId: 'root',
      email: 'same@example.com',
      password: PASSWORD,
    });
    if (!('mfaRequired' in login)) throw new Error('Expected MFA');
    const credential = { tenantId: 'root', challenge: login.challenge };
    const enrollment = await auth.beginMfa(credential);
    const enabled = await auth.confirmMfa({ credential, code: totp(enrollment.secret) });
    const rotated = await auth.regenerateRecoveryCodes({ token: enabled.token });
    expect(rotated.recoveryCodes).toHaveLength(10);
    expect(rotated.recoveryCodes).not.toContain(enabled.recoveryCodes[0]);
    await expect(auth.disableMfa({ token: enabled.token })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
    const again = await auth.signIn({
      tenantId: 'root',
      email: 'same@example.com',
      password: PASSWORD,
    });
    if (!('mfaRequired' in again)) throw new Error('Expected MFA');
    await expect(
      auth.recoverMfa({
        tenantId: 'root',
        challenge: again.challenge,
        code: enabled.recoveryCodes[0]!,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    await auth.recoverMfa({
      tenantId: 'root',
      challenge: again.challenge,
      code: rotated.recoveryCodes[0]!,
    });
  });
});

describe('passwordless and delivery', () => {
  it('delivers encrypted outbox messages with deduplication identifiers and verifies passwordless codes once', async () => {
    await identity();
    await auth.startPasswordless({
      tenantId: 'org',
      destination: 'same@example.com',
      channel: 'email',
      kind: 'code',
    });
    const sealed = JSON.stringify(await store.find('outbox'));
    await auth.dispatchOutbox();
    const token = messages[0]!.payload.token!;
    expect(sealed).not.toContain(`"${token}"`);
    await expect(
      auth.finishPasswordless({ tenantId: 'sibling', destination: 'same@example.com', token }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    await expect(
      auth.finishPasswordless({ tenantId: 'org', destination: 'other@example.com', token }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    const attempts = await Promise.allSettled(
      [1, 2].map(() =>
        auth.finishPasswordless({ tenantId: 'org', destination: 'same@example.com', token }),
      ),
    );
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(await auth.dispatchOutbox()).toEqual({ delivered: 0, failed: 0, abandoned: 0 });
  });

  it('requires verified phone ownership before SMS login', async () => {
    await identity();
    const login = session(
      await auth.signIn({ tenantId: 'org', email: 'same@example.com', password: PASSWORD }),
    );
    await auth.startPasswordless({
      tenantId: 'org',
      destination: '+15551234567',
      channel: 'sms',
      kind: 'code',
    });
    await auth.dispatchOutbox();
    expect(messages).toHaveLength(0);
    await auth.startPhoneVerification({ token: login.token }, { phone: '+15551234567' });
    await auth.dispatchOutbox();
    await auth.confirmPhoneVerification(
      { token: login.token },
      { phone: '+15551234567', code: messages[0]!.payload.token! },
    );
    await auth.startPasswordless({
      tenantId: 'org',
      destination: '+15551234567',
      channel: 'sms',
      kind: 'code',
    });
    await auth.dispatchOutbox();
    expect(
      session(
        await auth.finishPasswordless({
          tenantId: 'org',
          destination: '+15551234567',
          token: messages[1]!.payload.token!,
        }),
      ).token,
    ).toBeTruthy();
  });

  it('binds sealed values to their purpose and validates enabled feature configuration', () => {
    const sealed = encryptSecret('private value', SECRET, 'tenant:a');
    expect(decryptSecret(sealed, SECRET, 'tenant:a')).toBe('private value');
    expect(() => decryptSecret(sealed, SECRET, 'tenant:b')).toThrow();
    expect(() =>
      createAuth({
        store,
        secret: SECRET,
        baseURL: 'https://iam.example.com',
        signUpEnabled: true,
      }),
    ).toThrow('sendEmail');
    expect(() =>
      createAuth({
        store,
        secret: SECRET,
        baseURL: 'https://iam.example.com',
        passwordlessSms: true,
      }),
    ).toThrow('sendSms');
  });
});

// A minimal virtual authenticator generates real P-256 WebAuthn signatures. No verifier mocks.
function cbor(value: unknown): Buffer {
  const header = (major: number, size: number): Buffer =>
    size < 24
      ? Buffer.from([(major << 5) | size])
      : size < 256
        ? Buffer.from([(major << 5) | 24, size])
        : Buffer.from([(major << 5) | 25, size >> 8, size & 255]);
  if (typeof value === 'number') return header(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([header(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([
      header(5, value.size),
      ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]),
    ]);
  throw new Error('Unsupported CBOR test value');
}

it('registers and authenticates real passkey assertions while rejecting wrong tenant, origin, and replay', async () => {
  const user = await identity();
  const login = session(
    await auth.signIn({ tenantId: 'org', email: 'same@example.com', password: PASSWORD }),
  );
  const registration = await auth.beginPasskeyRegistration({ token: login.token });
  const credentialId = randomBytes(32);
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = key.publicKey.export({ format: 'jwk' });
  const cose = cbor(
    new Map<unknown, unknown>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x!, 'base64url')],
      [-3, Buffer.from(jwk.y!, 'base64url')],
    ]),
  );
  const rpHash = createHash('sha256').update('iam.example.com').digest();
  const regAuthData = Buffer.concat([
    rpHash,
    Buffer.from([0x45]),
    Buffer.alloc(4),
    Buffer.alloc(16),
    Buffer.from([0, credentialId.length]),
    credentialId,
    cose,
  ]);
  const regClientData = Buffer.from(
    JSON.stringify({
      type: 'webauthn.create',
      challenge: registration.options.challenge,
      origin: 'https://iam.example.com',
    }),
  );
  await auth.finishPasskeyRegistration(
    { token: login.token },
    {
      challengeId: registration.challengeId,
      response: {
        id: credentialId.toString('base64url'),
        rawId: credentialId.toString('base64url'),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: regClientData.toString('base64url'),
          attestationObject: cbor(
            new Map<unknown, unknown>([
              ['fmt', 'none'],
              ['attStmt', new Map()],
              ['authData', regAuthData],
            ]),
          ).toString('base64url'),
          transports: ['internal'],
        },
      },
    },
  );
  const authentication = await auth.beginPasskeyAuthentication({
    tenantId: 'org',
    email: 'same@example.com',
  });
  const authData = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const response = (origin = 'https://iam.example.com') => {
    const client = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: authentication.options.challenge, origin }),
    );
    return {
      id: credentialId.toString('base64url'),
      rawId: credentialId.toString('base64url'),
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: client.toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: sign(
          'sha256',
          Buffer.concat([authData, createHash('sha256').update(client).digest()]),
          key.privateKey,
        ).toString('base64url'),
        userHandle: Buffer.from(user.id).toString('base64url'),
      },
    };
  };
  await expect(
    auth.finishPasskeyAuthentication({
      tenantId: 'sibling',
      challengeId: authentication.challengeId,
      response: response(),
    }),
  ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
  await expect(
    auth.finishPasskeyAuthentication({
      tenantId: 'org',
      challengeId: authentication.challengeId,
      response: response('https://attacker.example'),
    }),
  ).rejects.toThrow();
  const authenticated = await auth.finishPasskeyAuthentication({
    tenantId: 'org',
    challengeId: authentication.challengeId,
    response: response(),
  });
  expect((await auth.authenticate({ token: authenticated.token })).session.mfa).toBe(true);
  await expect(
    auth.finishPasskeyAuthentication({
      tenantId: 'org',
      challengeId: authentication.challengeId,
      response: response(),
    }),
  ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
  const keys = await auth.listPasskeys({ token: authenticated.token });
  expect(keys).toHaveLength(1);
  await auth.deletePasskey({ token: authenticated.token }, { id: keys[0]!.id });
  await expect(auth.authenticate({ token: authenticated.token })).rejects.toMatchObject({
    code: 'UNAUTHENTICATED',
  });
});
