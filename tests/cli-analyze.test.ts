import { createRequire } from 'node:module';
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { betterIam } from '@better-iam/server';
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
const secret = 'cli-analyze-testing-secret-with-32-chars';

describe('analysis CLI', () => {
  it('prints findings and fails CI runs at the chosen severity', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'cli-analyze-test-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs'),
      filename = join(folder, 'iam.db'),
      output: string[] = [];
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(filename)}}),secret:${JSON.stringify(secret)},baseURL:'http://localhost:3000',permissions:{actions:['documents:read']}});\n`,
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
    const iam = betterIam({
      database: sqliteAdapter({ filename }),
      secret,
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read'] },
    });
    let token: string;
    try {
      const challenge = await iam.api.auth.signIn({
        tenantId,
        email: 'root@example.test',
        password: 'a strong cli root password',
      });
      if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
      const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
      token = (
        await iam.api.auth.confirmMfa({
          credential: { tenantId, challenge: challenge.challenge },
          code: authenticator.generate(enrollment.secret),
        })
      ).token;
      await iam.api.roles.create(
        { token },
        { tenantId, name: 'Idle', permissions: ['documents:read'] },
      );
    } finally {
      await iam.store.close();
    }
    const asRoot = { ...io, env: { ...io.env, BETTER_IAM_TOKEN: token } };

    await expect(runCli(['analyze', '--config', config], asRoot)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['analyze', '--config', config, '--tenant', tenantId, '--fail-on', 'urgent'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['migrate', '--config', config, '--fail-on', 'high'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['analyze', '--config', config, '--tenant', tenantId], io),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });

    // Only a low finding (the unused role): a high threshold passes, a low threshold fails.
    await runCli(
      ['analyze', '--config', config, '--tenant', tenantId, '--fail-on', 'high'],
      asRoot,
    );
    const report = JSON.parse(output.at(-1)!);
    expect(report.findings.map((finding: { kind: string }) => finding.kind)).toEqual([
      'unused-role',
    ]);
    await expect(
      runCli(['analyze', '--config', config, '--tenant', tenantId, '--fail-on', 'low'], asRoot),
    ).rejects.toMatchObject({ code: 'FINDINGS' });
    await runCli(
      ['analyze', '--config', config, '--tenant', tenantId, '--dormant-days', '30'],
      asRoot,
    );
    expect(JSON.parse(output.at(-1)!).dormantDays).toBe(30);
    expect(JSON.stringify(output)).not.toContain(token);

    // The certification worker is a deployment operation: no token, optional tenant filter.
    await runCli(['close-certifications', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({ closed: [], skipped: 0 });
    await expect(
      runCli(['close-certifications', '--config', config, '--fail-on', 'high'], io),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});
