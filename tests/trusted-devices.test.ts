import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const DAY = 24 * 60 * 60_000;

async function fixture(options: { deviceLifetimeMs?: number } = {}) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'trusted-devices-test-secret-with-32-chars!!',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      sessionLifetimeMs: 7 * DAY,
      sessionIdleTimeoutMs: DAY,
      now: () => clock,
      ...(options.deviceLifetimeMs !== undefined
        ? { trustedDeviceLifetimeMs: options.deviceLifetimeMs }
        : {}),
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const totp = (secret: string) => {
    const generator = authenticator.clone();
    generator.options = { epoch: clock };
    return generator.generate(secret);
  };
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const rootSession = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: totp(enrollment.secret),
    rememberDevice: true,
  });
  const rootCredential = { token: rootSession.token };
  const created = await iam.api.tenants.create(rootCredential, {
    parentId: root.tenant.id,
    name: 'Acme',
    type: 'organization',
    ownerEmail: 'owner@acme.test',
  });
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  // Alice enrolls an authenticator from her own session.
  const alice = await iam.api.identities.create(ownerCredential, {
    tenantId,
    email: 'alice@acme.test',
    name: 'Alice',
    password: 'a strong alice password',
  });
  const first = await iam.api.auth.signIn({
    tenantId,
    email: 'alice@acme.test',
    password: 'a strong alice password',
  });
  if (!('token' in first)) throw new Error('Unexpected MFA before enrollment');
  const aliceEnrollment = await iam.api.auth.beginMfa({ token: first.token });
  await iam.api.auth.confirmMfa({
    credential: { token: first.token },
    code: totp(aliceEnrollment.secret),
  });
  const signIn = (deviceToken?: string) =>
    iam.api.auth.signIn({
      tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
      ...(deviceToken === undefined ? {} : { deviceToken }),
    });
  const verify = async (challengeToken: string, rememberDevice: boolean) => {
    clock += 30_000; // a fresh TOTP step
    return iam.api.auth.verifyMfa({
      tenantId,
      challenge: challengeToken,
      code: totp(aliceEnrollment.secret),
      rememberDevice,
    });
  };
  return {
    iam,
    tenantId,
    alice,
    ownerCredential,
    rootSession,
    signIn,
    verify,
    code: () => totp(aliceEnrollment.secret),
    now: () => clock,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('trusted devices', () => {
  it('lets a remembered browser skip MFA within the policy window and forgets it on revocation or credential change', async () => {
    const f = await fixture();
    // Root administrators are never remembered.
    expect(f.rootSession.deviceToken).toBeUndefined();
    // Without a token, MFA is required; verifying with rememberDevice hands back a device token.
    const challenge = await f.signIn();
    if (!('mfaRequired' in challenge)) throw new Error('Alice must require MFA');
    const remembered = await f.verify(challenge.challenge, true);
    expect(remembered.deviceToken).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(remembered.deviceExpiresAt).toBe(f.now() + 30 * DAY);
    expect(remembered.session.trustedDeviceId).toBeUndefined();
    expect(remembered.session.mfa).toBe(true);
    // The token satisfies MFA on the next sign-in and the session records the device.
    const quick = await f.signIn(remembered.deviceToken);
    if (!('token' in quick)) throw new Error('Device token should skip MFA');
    expect(quick.session.mfa).toBe(true);
    expect(quick.session.method).toBe('password');
    const devices = await f.iam.api.auth.listTrustedDevices({ token: quick.token });
    expect(devices).toHaveLength(1);
    expect(quick.session.trustedDeviceId).toBe(devices[0]!.id);
    expect(devices[0]!.lastUsedAt).toBe(f.now());
    expect(JSON.stringify(devices)).not.toContain('tokenHash');
    // A wrong, foreign, or malformed token falls back to the challenge instead of failing.
    for (const token of ['nonsense', `${remembered.deviceToken}x`, 'a'.repeat(40)]) {
      const outcome = await f.signIn(token);
      expect('mfaRequired' in outcome).toBe(true);
    }
    // A tenant can shorten the window; the deployment ceiling still applies, and 0 disables it.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { trustedDeviceDays: 7 },
    });
    const again = await f.verify(
      ((await f.signIn('x'.repeat(40))) as { challenge: string }).challenge,
      true,
    );
    expect(again.deviceExpiresAt).toBe(f.now() + 7 * DAY);
    expect((await f.iam.api.auth.listTrustedDevices({ token: again.token })).length).toBe(2);
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { trustedDeviceDays: 0 },
    });
    expect('mfaRequired' in (await f.signIn(remembered.deviceToken))).toBe(true);
    const disabled = await f.verify(((await f.signIn()) as { challenge: string }).challenge, true);
    expect(disabled.deviceToken).toBeUndefined();
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: null,
    });
    // Expiry: the first device (30 days) outlives the second (7 days).
    f.advance(8 * DAY);
    expect('mfaRequired' in (await f.signIn(again.deviceToken))).toBe(true);
    const still = await f.signIn(remembered.deviceToken);
    if (!('token' in still)) throw new Error('The 30-day device should still vouch');
    expect((await f.iam.api.auth.listTrustedDevices({ token: still.token })).length).toBe(1);
    // Forgetting a device needs recent authentication; then the token stops working.
    f.advance(6 * 60_000);
    const [device] = await f.iam.api.auth.listTrustedDevices({ token: still.token });
    await expect(
      f.iam.api.auth.revokeTrustedDevice({ token: still.token }, { deviceId: device!.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = await f.signIn(remembered.deviceToken);
    if (!('token' in fresh)) throw new Error('Device should vouch');
    await f.iam.api.auth.revokeTrustedDevice({ token: fresh.token }, { deviceId: device!.id });
    expect('mfaRequired' in (await f.signIn(remembered.deviceToken))).toBe(true);
    // A password change forgets every remembered device.
    const before = await f.verify(((await f.signIn()) as { challenge: string }).challenge, true);
    expect(before.deviceToken).toBeDefined();
    await f.iam.api.auth.changePassword(
      { token: before.token },
      { currentPassword: 'a strong alice password', password: 'a brand new alice password!' },
    );
    const after = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a brand new alice password!',
      deviceToken: before.deviceToken,
    });
    expect('mfaRequired' in after).toBe(true);
    // The owner's original session expired with the clock; sign in again to read the trail.
    const ownerAgain = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    if (!('token' in ownerAgain)) throw new Error('Unexpected owner MFA');
    const trail = await f.iam.api.audit.list(
      { token: ownerAgain.token },
      { tenantId: f.tenantId, action: 'auth:device:*' },
    );
    expect(trail.map((event) => event.action)).toEqual(
      expect.arrayContaining(['auth:device:trust', 'auth:device:revoke']),
    );
  });

  it('carries the device token in its own cookie over HTTP and can be disabled for the deployment', async () => {
    const f = await fixture();
    const origin = 'http://localhost:3000';
    const json = { 'content-type': 'application/json', 'x-better-iam': '1', origin };
    const post = (path: string, body: unknown, cookie?: string) =>
      f.iam.handler(
        new Request(`${origin}/api/iam/${path}`, {
          method: 'POST',
          headers: cookie ? { ...json, cookie } : json,
          body: JSON.stringify(body),
        }),
      );
    const cookiesOf = (response: Response) =>
      Object.fromEntries(
        response.headers.getSetCookie().map((line) => {
          const [pair, ...attributes] = line.split(';');
          const [name, value] = pair!.split('=');
          return [
            name!,
            { value: value ?? '', maxAge: attributes.join(';').match(/Max-Age=(\d+)/)?.[1] },
          ];
        }),
      );
    const credentials = {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    };
    const challenge = (await (await post('auth/signIn', credentials)).json()) as {
      data: { challenge: string };
    };
    f.advance(30_000);
    const verified = await post('auth/verifyMfa', {
      tenantId: f.tenantId,
      challenge: challenge.data.challenge,
      code: f.code(),
      rememberDevice: true,
    });
    expect(verified.status).toBe(200);
    const issued = cookiesOf(verified);
    expect(issued['better-iam.session']?.value).toBeTruthy();
    expect(issued['better-iam.device']?.value).toBeTruthy();
    const { data } = (await verified.json()) as {
      data: { deviceToken: string; deviceExpiresAt: number };
    };
    // The cookie's age is computed on the authentication clock that stamped the expiry.
    expect(Number(issued['better-iam.device']!.maxAge)).toBe(
      Math.floor((data.deviceExpiresAt - f.now()) / 1000),
    );
    expect(decodeURIComponent(issued['better-iam.device']!.value)).toBe(data.deviceToken);
    // The device cookie alone lets the next password sign-in skip the challenge.
    const deviceCookie = `better-iam.device=${issued['better-iam.device']!.value}`;
    const quick = await post('auth/signIn', credentials, deviceCookie);
    const quickBody = (await quick.json()) as {
      data: { token?: string; mfaRequired?: true; session?: { trustedDeviceId?: string } };
    };
    expect(quickBody.data.mfaRequired).toBeUndefined();
    expect(quickBody.data.session?.trustedDeviceId).toBeTruthy();
    const sessionCookie = `better-iam.session=${cookiesOf(quick)['better-iam.session']!.value}`;
    // Forgetting every device clears the cookie and the next sign-in asks for the code again.
    const forgotten = await post(
      'auth/revokeTrustedDevices',
      {},
      `${sessionCookie}; ${deviceCookie}`,
    );
    expect(forgotten.status).toBe(200);
    expect(cookiesOf(forgotten)['better-iam.device']?.maxAge).toBe('0');
    const again = (await (await post('auth/signIn', credentials, deviceCookie)).json()) as {
      data: { mfaRequired?: true };
    };
    expect(again.data.mfaRequired).toBe(true);
    // The deployment can switch the feature off entirely, and rejects nonsense lifetimes.
    const off = await fixture({ deviceLifetimeMs: 0 });
    const offChallenge = await off.signIn();
    if (!('mfaRequired' in offChallenge)) throw new Error('MFA expected');
    const offResult = await off.verify(offChallenge.challenge, true);
    expect(offResult.deviceToken).toBeUndefined();
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'trusted-devices-test-secret-with-32-chars!!',
        baseURL: 'http://localhost:3000',
        authentication: { trustedDeviceLifetimeMs: 1000 },
      }),
    ).toThrow(/Trusted device lifetime/);
  });
});
