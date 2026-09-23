import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { encryptSecret, type DeliveryMessage } from '@better-iam/auth';
import { verifyAssertionToken } from '@better-iam/next';
import type { IamStore } from '@better-iam/core';
import {
  betterIam,
  verifyAssertion,
  verifyWebhookSignature,
  type WebhookDelivery,
} from '@better-iam/server';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const OLD = 'rotation-test-old-secret-with-plenty-of-characters-1';
const NEW = 'rotation-test-new-secret-with-plenty-of-characters-2';
const OTHER = 'rotation-test-unrelated-secret-with-many-characters-3';
const work = resolve('work');
const created: string[] = [];
const stores: IamStore[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) await store.close();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});

let clock = Date.now();
/** One deployment instance over `database`, as it would start with this secret configuration. */
function instance(database: IamStore, secret: string, previousSecrets?: string[]) {
  const inbox: DeliveryMessage[] = [];
  const deliveries: WebhookDelivery[] = [];
  const iam = betterIam({
    database,
    secret,
    ...(previousSecrets ? { previousSecrets } : {}),
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    events: {
      deliverWebhook: async (delivery) => {
        deliveries.push(delivery);
      },
    },
  });
  return { iam, inbox, deliveries };
}
const totp = (secret: string) => {
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  return generator.generate(secret) as string;
};
async function signInRoot(
  iam: ReturnType<typeof instance>['iam'],
  tenantId: string,
  password: string,
  mfaSecret: string,
) {
  const challenge = await iam.api.auth.signIn({ tenantId, email: 'root@example.test', password });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  return iam.api.auth.verifyMfa({
    tenantId,
    challenge: challenge.challenge,
    code: totp(mfaSecret),
  });
}
const signed = (delivery: WebhookDelivery, secret: string) =>
  verifyWebhookSignature({
    secret,
    timestamp: delivery.headers['x-better-iam-timestamp']!,
    body: delivery.body,
    signature: delivery.headers['x-better-iam-signature']!,
    now: clock,
  });

describe('deployment secret rotation', () => {
  it('keeps every sealed value and pending link working, re-seals, then runs on the new secret alone', async () => {
    clock = Date.now();
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);

    // --- before: a deployment on the old secret -------------------------------------------
    const before = instance(database, OLD);
    await before.iam.initialize();
    const root = await before.iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const tenantId = root.tenant.id;
    const challenge = await before.iam.api.auth.signIn({
      tenantId,
      email: 'root@example.test',
      password: 'a strong root test password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
    const enrollment = await before.iam.api.auth.beginMfa({
      tenantId,
      challenge: challenge.challenge,
    });
    const session = await before.iam.api.auth.confirmMfa({
      credential: { tenantId, challenge: challenge.challenge },
      code: totp(enrollment.secret),
    });
    const credential = { token: session.token };
    const hook = await before.iam.api.webhooks.create(credential, {
      tenantId,
      url: 'https://hooks.example.test/iam',
      events: ['*'],
    });
    const assertion = await before.iam.api.assertions.issue(credential, {
      tenantId,
      audience: 'billing',
    });
    // A password reset requested now: its email waits in the outbox, its link digest uses OLD.
    await before.iam.api.auth.requestPasswordReset({ tenantId, email: 'root@example.test' });

    // --- during: the new secret, with the old one listed ------------------------------------
    clock += 60_000;
    const during = instance(database, NEW, [OLD]);
    // Sessions are hashed without the secret: nobody is signed out by the rotation itself.
    const rootId = (await during.iam.api.auth.getSession(credential)).identity.id;
    await during.iam.auth.dispatchOutbox();
    const reset = during.inbox.find((message) => message.template === 'password-reset')!;
    expect(reset.payload.token).toEqual(expect.any(String));
    expect(during.deliveries.length).toBeGreaterThan(0);
    expect(during.deliveries.every((delivery) => signed(delivery, hook.secret))).toBe(true);
    await during.iam.api.auth.resetPassword({
      tenantId,
      token: reset.payload.token!,
      password: 'a rotated root test password',
    });
    clock += 60_000;
    expect(
      await signInRoot(during.iam, tenantId, 'a rotated root test password', enrollment.secret),
    ).toMatchObject({ token: expect.any(String) });
    // Downstream services verify with every key until the old assertions expire.
    const verify = (key: string | string[]) =>
      verifyAssertion(assertion.token, { key, audience: 'billing', now: clock });
    expect(verify(during.iam.assertionKeys()).sub).toBe(rootId);
    expect(() => verify(during.iam.assertionKey())).toThrow('Invalid signature');
    // The edge verifier takes the same list.
    const edge = (key: string | string[]) =>
      verifyAssertionToken(assertion.token, { key, audience: 'billing', now: clock });
    expect((await edge(during.iam.assertionKeys())).sub).toBe(rootId);
    await expect(edge(during.iam.assertionKey())).rejects.toThrow('Invalid signature');

    const pending = await during.iam.selfCheck();
    expect(pending.findings).toContainEqual(
      expect.objectContaining({ check: 'secret-rotation-pending', severity: 'warning', count: 2 }),
    );
    const plan = await during.iam.rotateSecrets({ dryRun: true });
    expect(plan).toMatchObject({
      resealed: { authMfa: 1, webhooks: 1 },
      unreadable: {},
      done: false,
    });
    expect((await during.iam.rotateSecrets({ dryRun: true })).resealed).toEqual(plan.resealed);
    expect(await during.iam.rotateSecrets()).toMatchObject({
      resealed: { authMfa: 1, webhooks: 1 },
      done: true,
    });
    // Nothing left under OLD; the current count also includes undelivered messages sealed with NEW.
    const again = await during.iam.rotateSecrets();
    expect(again).toMatchObject({ resealed: {}, unreadable: {}, done: true });
    expect(again.current).toBeGreaterThanOrEqual(2);
    const settled = await during.iam.selfCheck();
    expect(settled.findings.map((finding) => finding.check)).toContain(
      'previous-secrets-configured',
    );
    expect(settled.findings.map((finding) => finding.check)).not.toContain(
      'secret-rotation-pending',
    );

    // --- after: the old secret is gone ----------------------------------------------------
    clock += 60_000;
    const after = instance(database, NEW);
    expect(
      await signInRoot(after.iam, tenantId, 'a rotated root test password', enrollment.secret),
    ).toMatchObject({ token: expect.any(String) });
    await after.iam.api.auth.requestPasswordReset({ tenantId, email: 'root@example.test' });
    await after.iam.auth.dispatchOutbox();
    expect(after.deliveries.length).toBeGreaterThan(0);
    expect(after.deliveries.every((delivery) => signed(delivery, hook.secret))).toBe(true);
    expect((await after.iam.selfCheck()).findings.map((finding) => finding.check)).not.toContain(
      'unreadable-secrets',
    );

    // A secret replaced without listing the old one: nothing opens, and the self-check says so.
    const broken = instance(database, OTHER);
    const report = await broken.iam.selfCheck();
    expect(report.ok).toBe(false);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ check: 'unreadable-secrets', severity: 'error', count: 2 }),
    );
    expect((await broken.iam.rotateSecrets()).unreadable).toEqual({ authMfa: 1, webhooks: 1 });
  });

  it('never calls a partial rotation or a partial sample done', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const { iam } = instance(database, NEW, [OLD]);
    await iam.initialize();
    await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    await database.transaction(async (tx) => {
      for (let index = 0; index < 10; index++)
        await tx.insert('authMfa', {
          id: `p${index}`,
          tenantId: 't',
          identityId: `p${index}`,
          enabled: true,
          encryptedSecret: encryptSecret('JBSWY3DPEHPK3PXP', OLD, `mfa:p${index}`),
        });
    });
    // An interrupted run (here: a limit) re-seals the first records only.
    const partial = await iam.rotateSecrets({ limit: 5, batchSize: 5 });
    expect(partial).toMatchObject({ resealed: { authMfa: 5 }, complete: false, done: false });
    // A sample of those first records looks clean, but the check says it is only a sample.
    const sampled = await iam.selfCheck({ cap: 5 });
    expect(sampled.findings).toContainEqual(
      expect.objectContaining({ check: 'secret-rotation-unverified', severity: 'warning' }),
    );
    expect(sampled.findings.map((finding) => finding.check)).not.toContain(
      'previous-secrets-configured',
    );
    expect(await iam.rotateSecrets({ dryRun: true })).toMatchObject({
      resealed: { authMfa: 5 },
      complete: true,
      done: false,
    });
    expect(await iam.rotateSecrets()).toMatchObject({ complete: true, done: true });
    expect(await iam.rotateSecrets({ dryRun: true })).toMatchObject({ resealed: {}, done: true });
  });

  it('refuses unusable previous secrets', () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    for (const previousSecrets of [
      ['too short'],
      [NEW],
      [OLD, OLD],
      Array.from({ length: 6 }, (_, index) => `${OLD}-${index}`),
    ])
      expect(() =>
        betterIam({ database, secret: NEW, previousSecrets, baseURL: 'http://localhost:3000' }),
      ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('rotates from the CLI and fails on values no configured secret opens', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'rotation-test-'));
    created.push(folder);
    const file = join(folder, 'iam.db');
    const config = async (name: string, secret: string, previous: string[] = []) => {
      const path = join(folder, `${name}.config.mjs`);
      await writeFile(
        path,
        `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({ database: sqliteAdapter({ filename: ${JSON.stringify(file)} }), secret: ${JSON.stringify(secret)}, previousSecrets: ${JSON.stringify(previous)}, baseURL: 'http://localhost:3000' });\n`,
      );
      return path;
    };
    const output: string[] = [];
    const io = { out: (line: string) => output.push(line), env: {} };
    const rotating = await config('rotating', NEW, [OLD]);
    await runCli(['migrate', '--config', rotating], io);
    const store = sqliteAdapter({ filename: file });
    await store.transaction((tx) =>
      tx.insert('authMfa', {
        id: 'person',
        tenantId: 't',
        identityId: 'person',
        enabled: true,
        encryptedSecret: encryptSecret('JBSWY3DPEHPK3PXP', OLD, 'mfa:person'),
      }),
    );
    await store.close();
    await runCli(['rotate-secrets', '--config', rotating, '--dry-run'], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({ resealed: { authMfa: 1 }, done: false });
    await runCli(['rotate-secrets', '--config', rotating], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({ resealed: { authMfa: 1 }, done: true });
    await runCli(['rotate-secrets', '--config', rotating], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({ resealed: {}, current: 1 });
    await expect(
      runCli(['rotate-secrets', '--config', await config('wrong', OTHER)], io),
    ).rejects.toMatchObject({ code: 'UNREADABLE_SECRETS' });
    await expect(runCli(['rotate-secrets', '--limit', '5'], io)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });
});
