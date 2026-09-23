import { createRequire } from 'node:module';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { betterIam, periodBounds, periodOf, shiftPeriod } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
const secret = 'billing-cli-testing-secret-with-32-chars';

describe('billing CLI', () => {
  it('closes a month, sends budget alerts, records seats, and prints spend', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'billing-cli-test-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs');
    const filename = join(folder, 'iam.db');
    const output: string[] = [];
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(filename)}}),secret:${JSON.stringify(secret)},baseURL:'http://localhost:3000'});\n`,
    );
    const io = {
      out: (message: string) => output.push(message),
      env: {
        BETTER_IAM_ROOT_EMAIL: 'root@example.test',
        BETTER_IAM_ROOT_NAME: 'Root',
        BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
      } as NodeJS.ProcessEnv,
    };
    await runCli(['migrate', '--config', config], io);
    await runCli(['bootstrap', '--config', config], io);
    const rootId = JSON.parse(output.at(-1)!).tenant.id as string;
    const lastMonth = shiftPeriod(periodOf(Date.now(), 'UTC'), -1);
    const iam = betterIam({
      database: sqliteAdapter({ filename }),
      secret,
      baseURL: 'http://localhost:3000',
      // Creating an organization sends its owner invitation.
      authentication: { sendEmail: async () => undefined },
    });
    let token: string;
    let orgId: string;
    try {
      const challenge = await iam.api.auth.signIn({
        tenantId: rootId,
        email: 'root@example.test',
        password: 'a strong cli root password',
      });
      if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
      const enrollment = await iam.api.auth.beginMfa({
        tenantId: rootId,
        challenge: challenge.challenge,
      });
      token = (
        await iam.api.auth.confirmMfa({
          credential: { tenantId: rootId, challenge: challenge.challenge },
          code: authenticator.generate(enrollment.secret),
        })
      ).token;
      const root = { token };
      orgId = (
        await iam.api.tenants.create(root, {
          parentId: rootId,
          name: 'Acme',
          type: 'organization',
          ownerEmail: 'owner@acme.test',
        })
      ).tenant.id;
      await iam.api.billing.createMeter(root, {
        tenantId: rootId,
        key: 'builds',
        name: 'CI builds',
      });
      await iam.api.billing.setPrice(root, {
        tenantId: rootId,
        meter: 'builds',
        effectiveFrom: lastMonth,
        price: { model: 'per-unit', unitAmount: 0.5 },
      });
      await iam.billing.record({
        tenantId: orgId,
        meter: 'builds',
        quantity: 30,
        occurredAt: periodBounds(lastMonth, 'UTC').start + 3_600_000,
      });
      await iam.api.billing.createBudget(root, {
        tenantId: orgId,
        name: 'Builds',
        amount: 10,
        forecastAlerts: false,
      });
      await iam.billing.record({ tenantId: orgId, meter: 'builds', quantity: 30 });
    } finally {
      await iam.store.close();
    }

    await runCli(['billing-close', '--config', config], io);
    const closed = JSON.parse(output.at(-1)!);
    expect(closed).toMatchObject({ period: lastMonth, skipped: { existing: 0, empty: 0 } });
    expect(closed.issued).toEqual([
      expect.objectContaining({ accountId: orgId, totalMicros: 15_000_000 }),
    ]);
    // The new invoice is due in 30 days: no reminder yet.
    await runCli(['billing-reminders', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({ checked: 1, reminders: [] });
    await runCli(['billing-alerts', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      checked: 1,
      alerts: [
        expect.objectContaining({ threshold: 50 }),
        expect.objectContaining({ threshold: 80 }),
        expect.objectContaining({ threshold: 100 }),
      ],
    });
    // No seats meter is defined, so every tenant is skipped.
    await runCli(['billing-seats', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({ meter: 'seats', recorded: 0 });
    await runCli(
      [
        'spend',
        '--config',
        config,
        '--tenant',
        orgId,
        '--period',
        lastMonth,
        '--group-by',
        'meter',
      ],
      { ...io, env: { ...io.env, BETTER_IAM_TOKEN: token } },
    );
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      period: lastMonth,
      total: { costMicros: 15_000_000 },
      rows: [{ key: 'builds', label: 'CI builds' }],
    });
    await expect(
      runCli(['spend', '--config', config, '--tenant', orgId, '--group-by', 'nope'], {
        ...io,
        env: { ...io.env, BETTER_IAM_TOKEN: token },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});
