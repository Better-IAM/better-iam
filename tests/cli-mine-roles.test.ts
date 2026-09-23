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
const secret = 'cli-mining-testing-secret-with-32-chars!';

describe('role mining CLI', () => {
  it('prints suggestions and peer outliers', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'cli-mining-test-'));
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
        { tenantId, name: 'Reader', permissions: ['documents:read'] },
      );
      await iam.api.roles.create(
        { token },
        { tenantId, name: 'Viewer', permissions: ['documents:read'] },
      );
      // Root overrides every decision, so an invariant denying everyone is broken by the root itself.
      await iam.api.invariants.create(
        { token },
        {
          tenantId,
          name: 'Nobody reads x',
          subject: { everyone: true },
          action: 'documents:read',
          resource: { type: 'iam', id: 'x' },
          expect: 'deny',
        },
      );
    } finally {
      await iam.store.close();
    }
    const asRoot = { ...io, env: { ...io.env, BETTER_IAM_TOKEN: token } };

    await expect(runCli(['mine-roles', '--config', config], asRoot)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['analyze', '--config', config, '--tenant', tenantId, '--peer-by', 'manager'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['mine-roles', '--config', config, '--tenant', tenantId], io),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });
    await runCli(['mine-roles', '--config', config, '--tenant', tenantId], asRoot);
    const result = JSON.parse(output.at(-1)!);
    expect(result.summary['duplicate-roles']).toBe(1);
    expect(result.suggestions[0].roles.map((role: { name: string }) => role.name).sort()).toEqual([
      'Reader',
      'Viewer',
    ]);
    expect(result.peers).toMatchObject({ peerBy: 'manager', outliers: [] });
    await expect(
      runCli(
        ['mine-roles', '--config', config, '--tenant', tenantId, '--peer-by', 'attribute:x'],
        asRoot,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(JSON.stringify(output)).not.toContain(token);

    await runCli(['check-invariants', '--config', config, '--tenant', tenantId], asRoot);
    expect(JSON.parse(output.at(-1)!).summary).toEqual({ passed: 0, failed: 1, errors: 0 });
    await expect(
      runCli(
        ['check-invariants', '--config', config, '--tenant', tenantId, '--fail-on-broken'],
        asRoot,
      ),
    ).rejects.toMatchObject({ code: 'INVARIANTS_BROKEN' });
    await expect(runCli(['check-invariants', '--config', config], asRoot)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['mine-roles', '--config', config, '--tenant', tenantId, '--fail-on-broken'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    // The scheduled monitor needs no token and reports each break once.
    await runCli(['monitor-invariants', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      checked: 1,
      broken: [{ name: 'Nobody reads x' }],
    });
    await runCli(['monitor-invariants', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({ checked: 1, broken: [], restored: [] });
  });
});
