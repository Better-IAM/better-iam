import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Identity } from '@better-iam/core';
import {
  characterClasses,
  isCommonPassword,
  pwnedPasswords,
  type DeliveryMessage,
  type PasswordPolicyOptions,
} from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(passwordPolicy?: PasswordPolicyOptions) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'password-policy-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
      passwordPolicy,
    },
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
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
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    { parentId: root.tenant.id, name: 'Acme', type: 'organization', ownerEmail: 'owner@acme.test' },
  );
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
  const signIn = async (email: string, password: string) => {
    const result = await iam.api.auth.signIn({ tenantId, email, password });
    if (!('token' in result)) throw new Error('Unexpected MFA');
    return { token: result.token };
  };
  return {
    iam,
    database,
    inbox,
    tenantId,
    ownerCredential,
    signIn,
    setPolicy: (authPolicy: Record<string, unknown>) =>
      iam.api.tenants.setAuthPolicy(ownerCredential, { tenantId, authPolicy: authPolicy as never }),
    create: (name: string, password: string) =>
      iam.api.identities.create(ownerCredential, {
        tenantId,
        email: `${name.toLowerCase().replace(/\s+/g, '.')}@acme.test`,
        name,
        password,
      }),
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('password policy', () => {
  it('screens common, sequential and low-variety passwords and counts character classes', () => {
    for (const weak of [
      'password1234',
      'P@ssw0rd1234',
      'aaaaaaaaaaaaaa',
      'abababababab',
      'qwertyuiopasdf',
      'abcdefghijklmnop',
      '987654321098',
      'Correct Horse Battery Staple',
    ])
      expect(isCommonPassword(weak), weak).toBe(true);
    for (const fine of ['a strong alice password', 'twelve chars!', 'Tr0ub4dor&3xyz'])
      expect(isCommonPassword(fine), fine).toBe(false);
    expect(characterClasses('abc')).toBe(1);
    expect(characterClasses('aB3!')).toBe(4);
    expect(characterClasses('a strong password')).toBe(2);
  });

  it('checks breaches with k-anonymity and fails open unless configured otherwise', async () => {
    const password = 'a password from a breach';
    const digest = createHash('sha1').update(password).digest('hex').toUpperCase();
    const requested: string[] = [];
    const corpus = (count: number) =>
      (async (url: string | URL | Request) => {
        requested.push(String(url));
        return new Response(
          `0000000000000000000000000000000000A:1\r\n${digest.slice(5)}:${count}\r\n`,
        );
      }) as typeof fetch;
    expect(await pwnedPasswords({ fetch: corpus(3) })(password)).toBe(true);
    expect(requested[0]).toBe(`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`);
    expect(requested[0]).not.toContain(digest.slice(5));
    expect(await pwnedPasswords({ fetch: corpus(3), threshold: 10 })(password)).toBe(false);
    expect(await pwnedPasswords({ fetch: corpus(3) })('an entirely different one')).toBe(false);
    const offline = (async () => {
      throw new Error('offline');
    }) as typeof fetch;
    expect(await pwnedPasswords({ fetch: offline })(password)).toBe(false);
    await expect(
      pwnedPasswords({ fetch: offline, failClosed: true })(password),
    ).rejects.toMatchObject({ code: 'PASSWORD_CHECK_UNAVAILABLE', status: 503 });
  });

  it('applies deployment screening (breach corpus, custom rule, common list) to every password path', async () => {
    const f = await fixture({
      isBreached: async (password) => password === 'a breached but long password',
      check: (password, context) =>
        password.toLowerCase().includes('acme') && context.tenantId
          ? 'Do not use the company name'
          : undefined,
    });
    await expect(f.create('Bob', 'a breached but long password')).rejects.toMatchObject({
      code: 'BREACHED_PASSWORD',
    });
    await expect(f.create('Bob', 'my acme password is long')).rejects.toMatchObject({
      code: 'WEAK_PASSWORD',
      message: 'Do not use the company name',
    });
    await expect(f.create('Bob', 'password1234')).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
    await f.create('Bob', 'a strong bob password');
    const bob = await f.signIn('bob@acme.test', 'a strong bob password');
    await expect(
      f.iam.api.auth.changePassword(bob, {
        currentPassword: 'a strong bob password',
        password: 'a breached but long password',
      }),
    ).rejects.toMatchObject({ code: 'BREACHED_PASSWORD' });
  });

  it('validates and enforces tenant complexity and personal-information rules', async () => {
    const f = await fixture();
    for (const authPolicy of [
      { passwordHistory: 0 },
      { passwordHistory: 25 },
      { passwordMaxAgeDays: 0 },
      { passwordMinClasses: 5 },
      { passwordMinClasses: 1 },
      { passwordRejectPersonalInfo: 'yes' },
    ])
      await expect(f.setPolicy(authPolicy)).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    await f.setPolicy({ passwordMinClasses: 3 });
    await expect(f.create('Dave', 'a strong dave password')).rejects.toMatchObject({
      code: 'WEAK_PASSWORD',
    });
    await f.create('Dave', 'Strong Pass For D 42');

    await f.setPolicy({ passwordRejectPersonalInfo: true });
    await expect(f.create('Erin Walsh', 'walsh has a long password')).rejects.toMatchObject({
      code: 'WEAK_PASSWORD',
    });
    await expect(f.create('Frank', 'my name is frank really')).rejects.toMatchObject({
      code: 'WEAK_PASSWORD',
    });
    await f.create('Erin Walsh', 'a long unrelated passphrase');
  });

  it('refuses reuse within the tenant history and keeps a bounded history', async () => {
    const f = await fixture();
    await f.setPolicy({ passwordHistory: 2 });
    await f.create('Alice', 'first alice passphrase');
    const change = async (from: string, to: string) =>
      f.iam.api.auth.changePassword(await f.signIn('alice@acme.test', from), {
        currentPassword: from,
        password: to,
      });
    await change('first alice passphrase', 'second alice passphrase');
    await expect(change('second alice passphrase', 'first alice passphrase')).rejects.toMatchObject(
      { code: 'PASSWORD_REUSED' },
    );
    await expect(
      change('second alice passphrase', 'second alice passphrase'),
    ).rejects.toMatchObject({ code: 'PASSWORD_REUSED' });
    await change('second alice passphrase', 'third alice passphrase');
    // Two back is outside a history of 2 (current + one previous).
    await change('third alice passphrase', 'first alice passphrase');
    const alice = (await f.database.find<Identity>('identities', { email: 'alice@acme.test' }))[0]!;
    expect(await f.database.find('passwordHistory', { identityId: alice.id })).toHaveLength(3);
    expect(alice.passwordChangedAt).toBeTypeOf('number');

    // Deleting the identity removes its history.
    await f.iam.api.identities.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(await f.database.find('passwordHistory', { identityId: alice.id })).toHaveLength(0);
  });

  it('expires passwords after the maximum age and recovers through reset', async () => {
    const f = await fixture();
    await f.setPolicy({ passwordMaxAgeDays: 30 });
    await f.create('Gina', 'a strong gina password');
    await f.signIn('gina@acme.test', 'a strong gina password');
    f.advance(31 * 86_400_000);
    await expect(f.signIn('gina@acme.test', 'a strong gina password')).rejects.toMatchObject({
      code: 'PASSWORD_EXPIRED',
      status: 403,
    });
    // A wrong password still reads as invalid credentials: expiry is never an oracle.
    await expect(f.signIn('gina@acme.test', 'not the right password')).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    const gina = (await f.database.find<Identity>('identities', { email: 'gina@acme.test' }))[0]!;
    await f.database.transaction((tx) => f.iam.auth.issuePasswordReset(tx, gina));
    await f.iam.auth.dispatchOutbox();
    const reset = f.inbox.filter((message) => message.template === 'password-reset').at(-1)!;
    await f.iam.api.auth.resetPassword({
      tenantId: f.tenantId,
      token: reset.payload.token!,
      password: 'a renewed gina password',
    });
    await f.signIn('gina@acme.test', 'a renewed gina password');
  });
});
