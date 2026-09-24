import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { runCli } from '@better-iam/cli';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';

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
const secret = 'cli-threats-testing-secret-with-32-chars';

describe('threat detection CLI', () => {
  it('runs detection as a deployment operation, per tenant and in bounded batches', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'cli-threats-test-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs'),
      filename = join(folder, 'iam.db'),
      output: string[] = [];
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
    const tenantId = JSON.parse(output.at(-1)!).tenant.id as string;

    // No credential: the first run reads the day's events of every active tenant, and a quiet trail raises nothing.
    await runCli(['detect-threats', '--config', config], io);
    const first = JSON.parse(output.at(-1)!);
    expect(first).toMatchObject({
      tenants: 1,
      detections: 0,
      incidentsOpened: 0,
      responses: 0,
      braked: 0,
      chainBreaks: 0,
      pending: 0,
    });
    expect(first.eventsScanned).toBeGreaterThan(0);
    await runCli(['detect-threats', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({ tenants: 1, eventsScanned: 0 });

    for (const flags of [
      ['--max-events', '0'],
      ['--max-events', '20001'],
      ['--max-events', 'many'],
      ['--fail-on', 'high'],
    ])
      await expect(
        runCli(['detect-threats', '--config', config, ...flags], io),
      ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['detect-threats', '--config', config, '--tenant', 'no-such-tenant'], io),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // A failed sign-in lands in the chain; editing it afterwards breaks the chain, which the next run reports.
    const iam = betterIam({
      database: sqliteAdapter({ filename }),
      secret,
      baseURL: 'http://localhost:3000',
    });
    try {
      await expect(
        iam.api.auth.signIn({ tenantId, email: 'root@example.test', password: 'not the password' }),
      ).rejects.toBeTruthy();
      // The refusal answers first and records the failure right after.
      await iam.auth.settleBookkeeping();
      const [newest] = (await iam.store.find<AuditEvent>('audit', { tenantId })).sort(
        (a, b) => b.sequence! - a.sequence!,
      );
      expect(newest!.action).toBe('auth:signin:fail');
      await iam.store.transaction((tx) =>
        tx.put('audit', { ...newest!, metadata: { ...newest!.metadata, reason: 'forged' } }),
      );
    } finally {
      await iam.store.close();
    }
    await runCli(['detect-threats', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      tenants: 1,
      eventsScanned: 1,
      detections: 1,
      incidentsOpened: 1,
      chainBreaks: 1,
      pending: 0,
    });

    // The detection recorded its own events (threat:detection, threat:incident-open); one event per run leaves the
    // rest pending for the next run, which continues where this one stopped.
    await runCli(['detect-threats', '--config', config, '--max-events', '1'], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      eventsScanned: 1,
      detections: 0,
      chainBreaks: 0,
      pending: 1,
    });
    await runCli(['detect-threats', '--config', config], io);
    const last = JSON.parse(output.at(-1)!);
    expect(last).toMatchObject({ detections: 0, chainBreaks: 0, pending: 0 });
    expect(last.eventsScanned).toBeGreaterThan(0);
  });
});
