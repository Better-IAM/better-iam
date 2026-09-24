import { afterEach, describe, expect, it } from 'vitest';
import type { Session } from '@better-iam/core';
import { describeUserAgent, renderDeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

/** Security review regressions (session e15e8e) for the authentication service. */
describe('security notice content', () => {
  const phishing =
    'Mozilla/5.0 ACTION REQUIRED: your account is locked, restore access at https://evil.example/verify';
  it('never quotes the attacker-chosen User-Agent in sign-in notices', () => {
    for (const template of ['new-sign-in', 'sign-in-failures']) {
      const rendered = renderDeliveryMessage({
        template,
        to: 'a@example.test',
        payload: { userAgent: phishing, ip: '203.0.113.7', attempts: '5', method: 'password' },
      })!;
      for (const part of [rendered.text, rendered.html]) {
        expect(part, template).not.toContain('evil.example');
        expect(part, template).not.toContain('ACTION REQUIRED');
        expect(part, template).toContain('an unrecognized browser or app · 203.0.113.7');
      }
    }
    expect(describeUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1')).toBe(
      'Safari on iOS',
    );
  });
  it('keeps subjects on one line whatever names they interpolate', () => {
    const rendered = renderDeliveryMessage({
      template: 'team-join-request',
      to: 'maintainer@example.test',
      payload: { name: 'Bob\r\nBcc: victim@example.test', team: 'Ops\u2028X', teamId: 't1' },
    });
    if (rendered) expect(rendered.subject).not.toMatch(/[\r\n\u2028\u2029]/);
  });
  it('replaces control characters in display names at self sign-up', async () => {
    const f = await organizationFixture({
      authentication: { signUpEnabled: true } as never,
    });
    const created = await f.iam.api.auth.signUp({
      tenantId: f.tenantId,
      email: 'mallory@acme.test',
      name: 'Mallory\r\nBcc: victim@example.test',
      password: 'a strong mallory password',
    });
    expect(created.identity.name).toBe('Mallory  Bcc: victim@example.test');
  });
});
describe('passwordless codes', () => {
  it('keeps only the newest code or link of a destination valid', async () => {
    const f = await organizationFixture({
      authentication: { passwordlessEmail: true } as never,
    });
    await f.member('alice');
    const start = (kind: 'code' | 'magic-link') =>
      f.iam.api.auth.startPasswordless({
        tenantId: f.tenantId,
        destination: 'alice@acme.test',
        channel: 'email',
        kind,
      });
    const latestToken = async () => {
      await f.iam.auth.dispatchOutbox();
      const sent = f.inbox.filter((message) => message.to === 'alice@acme.test');
      return sent[sent.length - 1]!.payload.token!;
    };
    await start('code');
    const first = await latestToken();
    await start('magic-link');
    const link = await latestToken();
    await start('code');
    const second = await latestToken();
    const finish = (token: string) =>
      f.iam.api.auth.finishPasswordless({
        tenantId: f.tenantId,
        destination: 'alice@acme.test',
        token,
      });
    for (const stale of [first, link])
      if (stale !== second)
        await expect(finish(stale)).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    expect(await finish(second)).toHaveProperty('token');
  });
});

describe('mailed links and codes', () => {
  it('drop a password set before the address was proven, at the first emailed sign-in', async () => {
    const f = await organizationFixture({
      authentication: { passwordlessEmail: true, signUpEnabled: true } as never,
    });
    // Someone registers the victim's address with a password of their own. Email verification is required here, so
    // that password is useless until the address is verified, which only the real owner can do.
    await f.iam.api.auth.signUp({
      tenantId: f.tenantId,
      email: 'victim@acme.test',
      name: 'Victim',
      password: 'attacker chosen password',
    });
    await expect(
      f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'victim@acme.test',
        password: 'attacker chosen password',
      }),
    ).rejects.toMatchObject({ code: 'EMAIL_UNVERIFIED' });
    // The real owner signs in with an emailed link, verifying the address: the squatter's password must not start
    // working now.
    await f.iam.api.auth.startPasswordless({
      tenantId: f.tenantId,
      destination: 'victim@acme.test',
      channel: 'email',
      kind: 'magic-link',
    });
    await f.iam.auth.dispatchOutbox();
    const link = f.inbox.filter((message) => message.template === 'magic-link').at(-1)!;
    const owner = await f.iam.api.auth.finishPasswordless({
      tenantId: f.tenantId,
      destination: 'victim@acme.test',
      token: link.payload.token!,
    });
    expect(owner).toHaveProperty('token');
    await expect(
      f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'victim@acme.test',
        password: 'attacker chosen password',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('leave administrator-created accounts alone at their first emailed sign-in', async () => {
    const f = await organizationFixture({
      authentication: { passwordlessEmail: true, requireEmailVerification: false } as never,
    });
    await f.member('carol');
    const earlier = await f.signIn('carol');
    await f.iam.api.auth.startPasswordless({
      tenantId: f.tenantId,
      destination: 'carol@acme.test',
      channel: 'email',
      kind: 'code',
    });
    await f.iam.auth.dispatchOutbox();
    const code = f.inbox.filter((message) => message.template === 'code').at(-1)!;
    await f.iam.api.auth.finishPasswordless({
      tenantId: f.tenantId,
      destination: 'carol@acme.test',
      token: code.payload.token!,
    });
    // The password an administrator set, and the session it opened, still work.
    expect((await f.iam.authenticate({ token: earlier.token })).identity.email).toBe(
      'carol@acme.test',
    );
    expect(await f.signIn('carol')).toHaveProperty('token');
  });

  it('are bound to the address they were sent to', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await f.iam.api.identities.requestPasswordReset(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    await f.iam.auth.dispatchOutbox();
    const reset = f.inbox.filter((message) => message.template === 'password-reset').at(-1)!;
    // The address changes behind the auth service's back (as an identity provider or SCIM could change it).
    await f.iam.store.transaction(async (tx) => {
      const row = (await tx.get<{ email: string }>('identities', alice.id))!;
      await tx.put('identities', { ...row, email: 'alice.new@acme.test' } as never);
    });
    await expect(
      f.iam.api.auth.resetPassword({
        tenantId: f.tenantId,
        token: reset.payload.token!,
        password: 'a brand new alice password',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
  });

  it('answer passkey sign-in starts alike for unknown addresses and accounts without passkeys', async () => {
    const f = await organizationFixture({
      authentication: { passkeys: { rpID: 'localhost', rpName: 'IAM' } } as never,
    });
    await f.member('alice');
    const begin = (email: string) =>
      f.iam.api.auth.beginPasskeyAuthentication({ tenantId: f.tenantId, email });
    const known = await begin('alice@acme.test');
    const unknown = await begin('nobody@acme.test');
    for (const answer of [known, unknown]) {
      expect(answer.options.allowCredentials).toHaveLength(1);
      expect(typeof answer.challengeId).toBe('string');
    }
    // Stable per address, so repeating the question reveals nothing either.
    expect((await begin('nobody@acme.test')).options.allowCredentials).toEqual(
      unknown.options.allowCredentials,
    );
  });
});

describe('reauthentication', () => {
  it('refuses an expired password once verified, so fresh sessions cannot dodge passwordMaxAgeDays', async () => {
    const f = await organizationFixture();
    await f.iam.api.tenants.setAuthPolicy(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      authPolicy: { passwordMaxAgeDays: 30 },
    });
    await f.member('alice');
    f.advance(29 * day);
    const session = { token: (await f.signIn('alice')).token };
    const renewed = await f.iam.api.auth.reauthenticate(session, {
      password: 'a strong alice password',
    });
    if (!('token' in renewed)) throw new Error('Unexpected MFA');
    f.advance(2 * day);
    // A wrong password still reads as invalid; the right one is refused as expired.
    await expect(
      f.iam.api.auth.reauthenticate({ token: renewed.token }, { password: 'wrong password!!' }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(
      f.iam.api.auth.reauthenticate(
        { token: renewed.token },
        { password: 'a strong alice password' },
      ),
    ).rejects.toMatchObject({ code: 'PASSWORD_EXPIRED' });
  });
});

describe('identity expiry at the authentication layer', () => {
  it('refuses sign-in and session resolution past expiresAt, before the purge worker runs', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice', { expiresAt: f.now() + day });
    const session = await f.signIn('alice');
    expect((await f.iam.authenticate({ token: session.token })).identity.id).toBe(alice.id);
    f.advance(day + 1);
    // Still active in storage: the worker has not run.
    expect((await f.iam.store.get<{ status: string }>('identities', alice.id))?.status).toBe(
      'active',
    );
    // The existing session no longer resolves, for plain authentication and getSession alike.
    await expect(f.iam.authenticate({ token: session.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(f.iam.api.auth.getSession({ token: session.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // A correct password is refused like a disabled account's, and records no failed attempt.
    await expect(f.signIn('alice')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const sessions = await f.iam.store.find<Session>('sessions', { identityId: alice.id });
    expect(sessions.every((row) => row.id === session.session.id)).toBe(true);
    const failures = await f.iam.store.find<{ action: string; actorId?: string }>('audit', {
      tenantId: f.tenantId,
      action: 'auth:signin:fail',
    });
    expect(failures.filter((event) => event.actorId === alice.id)).toEqual([]);
  });
});
