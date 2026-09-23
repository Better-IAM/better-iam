import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(signInNotifications: boolean) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'security-activity-test-secret-with-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      signInNotifications,
    },
    tenantDefaults: {},
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  // The owner is created through a root-signed invitation without needing root's MFA session here.
  const created = await iam.store.transaction(async (tx) => {
    const owner = await iam.auth.createIdentity(tx, {
      tenantId: root.tenant.id,
      email: 'owner@example.test',
      name: 'Owner',
      password: 'a strong tenant owner password',
      emailVerified: true,
    });
    return owner;
  });
  void created;
  const signIn = (client?: { userAgent?: string; ip?: string; label?: string }) =>
    iam.auth.withClient(client, () =>
      iam.api.auth.signIn({
        tenantId: root.tenant.id,
        email: 'owner@example.test',
        password: 'a strong tenant owner password',
      }),
    );
  const alerts = () => inbox.filter((message) => message.template === 'new-sign-in');
  return { iam, inbox, tenantId: root.tenant.id, signIn, alerts };
}

describe('security activity and new sign-in alerts', () => {
  it('emails a person about sessions from unfamiliar clients only, and lists their own authentication trail', async () => {
    const f = await fixture(true);
    // No client details: nothing to compare, no email.
    const bare = await f.signIn();
    if (!('token' in bare)) throw new Error('Unexpected MFA');
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(0);
    // First sign-in from a laptop: email with the client details.
    const laptop = { userAgent: 'Mozilla/5.0 (Macintosh)', ip: '203.0.113.7', label: 'Laptop' };
    const first = await f.signIn(laptop);
    if (!('token' in first)) throw new Error('Unexpected MFA');
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(1);
    expect(f.alerts()[0]).toMatchObject({
      to: 'owner@example.test',
      payload: {
        sessionId: first.session.id,
        method: 'password',
        userAgent: laptop.userAgent,
        ip: laptop.ip,
        label: 'Laptop',
      },
    });
    // The same client again while the first session is alive: no email. A new phone: email.
    await f.signIn(laptop);
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(1);
    const phone = { userAgent: 'Mozilla/5.0 (iPhone)', ip: '198.51.100.2' };
    await f.signIn(phone);
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(2);
    // A tenant can switch alerts off even though the deployment enables them (the policy field is validated).
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'security-activity-test-secret-with-32-chars',
        baseURL: 'http://localhost:3000',
        tenantDefaults: { authPolicy: { notifyNewSignIn: 'no' as never } },
      }),
    ).toThrow(/notifyNewSignIn/);
    await f.iam.store.transaction(async (tx) => {
      const realm = (await tx.get('tenants', f.tenantId))!;
      await tx.put('tenants', { ...realm, authPolicy: { notifyNewSignIn: false } });
    });
    await f.signIn({ userAgent: 'curl/8', ip: '192.0.2.9' });
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(2);
    // The person's own trail lists auth events newest first and nothing else.
    const events = await f.iam.api.auth.listSecurityEvents({ token: first.token }, { limit: 10 });
    expect(events.length).toBeGreaterThanOrEqual(5);
    expect(events.every((event) => event.action.startsWith('auth:'))).toBe(true);
    expect(events[0]!.timestamp).toBeGreaterThanOrEqual(events.at(-1)!.timestamp);
    expect(events.map((event) => event.action)).toEqual(
      expect.arrayContaining(['auth:session:create', 'auth:identity:create']),
    );
    expect(JSON.stringify(events)).not.toContain('actorId');
    await expect(
      f.iam.api.auth.listSecurityEvents({ token: first.token }, { limit: 0 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Root's own events never leak into the owner's trail.
    const rootEvents = (await f.iam.store.find('audit', { tenantId: f.tenantId })).filter(
      (event) => event.actorId !== first.session.identityId,
    );
    expect(rootEvents.length).toBeGreaterThan(0);
    expect(events.map((event) => event.id)).not.toEqual(
      expect.arrayContaining(rootEvents.map((event) => event.id)),
    );
  });

  it('stays silent when the deployment leaves notifications off', async () => {
    const f = await fixture(false);
    await f.signIn({ userAgent: 'Mozilla/5.0 (Macintosh)', ip: '203.0.113.7' });
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(0);
    // A tenant may still opt in.
    await f.iam.store.transaction(async (tx) => {
      const realm = (await tx.get('tenants', f.tenantId))!;
      await tx.put('tenants', { ...realm, authPolicy: { notifyNewSignIn: true } });
    });
    await f.signIn({ userAgent: 'Mozilla/5.0 (Windows)', ip: '203.0.113.8' });
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(1);
  });
});
