import { createRequire } from 'node:module';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
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
    // better-sqlite3 releases the file handle on close; a failed test may leave it to garbage collection.
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'cli-config-test-'));
  created.push(folder);
  return folder;
}
const secret = 'cli-config-testing-secret-with-32-chars!';

describe('configuration CLI', () => {
  it('exports, plans, and applies a tenant configuration as the token holder', async () => {
    const folder = await directory(),
      config = join(folder, 'better-iam.config.mjs'),
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
    // A root session (MFA enrolled) from a separate connection to the same database.
    const iam = betterIam({
      database: sqliteAdapter({ filename }),
      secret,
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read'] },
    });
    let session: { token: string };
    try {
      const challenge = await iam.api.auth.signIn({
        tenantId,
        email: 'root@example.test',
        password: 'a strong cli root password',
      });
      if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
      const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
      session = await iam.api.auth.confirmMfa({
        credential: { tenantId, challenge: challenge.challenge },
        code: authenticator.generate(enrollment.secret),
      });
    } finally {
      await iam.store.close();
    }
    const asRoot = { ...io, env: { ...io.env, BETTER_IAM_TOKEN: session.token } };
    // Argument validation and the token requirement.
    await expect(runCli(['config-export', '--config', config], io)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['config-plan', '--config', config, '--tenant', tenantId], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['config-export', '--config', config, '--tenant', tenantId, '--input', 'x'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['config-export', '--config', config, '--tenant', tenantId], io),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });
    // The root tenant starts with nothing but its protected owner role, which is never exported.
    await runCli(['config-export', '--config', config, '--tenant', tenantId], asRoot);
    expect(JSON.parse(output.at(-1)!)).toEqual({
      version: 1,
      resourceTypes: [],
      policies: [],
      roles: [],
      groups: [],
      bindings: [],
      packages: [],
    });
    const input = join(folder, 'tenant.json');
    await writeFile(
      input,
      JSON.stringify({
        version: 1,
        roles: [{ name: 'Reader', permissions: ['documents:read'] }],
        groups: [{ name: 'Readers' }],
        bindings: [{ group: 'Readers', role: 'Reader' }],
      }),
    );
    await runCli(
      ['config-plan', '--config', config, '--tenant', tenantId, '--input', input],
      asRoot,
    );
    const plan = JSON.parse(output.at(-1)!);
    expect(plan.summary).toEqual({ create: 3, update: 0, delete: 0, unchanged: 0 });
    expect(plan.applied).toBeUndefined();
    await runCli(
      ['config-apply', '--config', config, '--tenant', tenantId, '--input', input, '--prune'],
      asRoot,
    );
    const applied = JSON.parse(output.at(-1)!);
    expect(applied).toMatchObject({ applied: true, prune: true });
    expect(applied.summary).toEqual({ create: 3, update: 0, delete: 0, unchanged: 0 });
    const exported = join(folder, 'exported.json');
    await runCli(
      ['config-export', '--config', config, '--tenant', tenantId, '--output', exported],
      asRoot,
    );
    expect(JSON.parse(output.at(-1)!)).toEqual({ tenantId, output: resolve(exported) });
    expect(JSON.parse(await readFile(exported, 'utf8'))).toMatchObject({
      roles: [{ name: 'Reader', permissions: ['documents:read'] }],
      groups: [{ name: 'Readers', members: [] }],
      bindings: [{ group: 'Readers', role: 'Reader' }],
    });
    // Applying the export is a no-op.
    await runCli(
      ['config-apply', '--config', config, '--tenant', tenantId, '--input', exported],
      asRoot,
    );
    expect(JSON.parse(output.at(-1)!).summary).toEqual({
      create: 0,
      update: 0,
      delete: 0,
      unchanged: 3,
    });
    // --fail-on-drift turns a plan into a check: clean passes, drift exits non-zero after printing the plan.
    await runCli(
      [
        'config-plan',
        '--config',
        config,
        '--tenant',
        tenantId,
        '--input',
        exported,
        '--fail-on-drift',
      ],
      asRoot,
    );
    expect(JSON.parse(output.at(-1)!).summary.unchanged).toBe(3);
    await writeFile(
      input,
      JSON.stringify({
        version: 1,
        roles: [
          { name: 'Reader', permissions: ['documents:read'] },
          { name: 'Writer', permissions: ['documents:read'] },
        ],
      }),
    );
    await expect(
      runCli(
        [
          'config-plan',
          '--config',
          config,
          '--tenant',
          tenantId,
          '--input',
          input,
          '--fail-on-drift',
        ],
        asRoot,
      ),
    ).rejects.toMatchObject({ code: 'CONFIG_DRIFT' });
    expect(JSON.parse(output.at(-1)!).summary.create).toBe(1);
    // The digest is a deployment operation; this configuration has no mail transport.
    await expect(
      runCli(['digest', '--config', config, '--within-days', '7'], io),
    ).rejects.toMatchObject({ code: 'DELIVERY_REQUIRED' });
    await expect(runCli(['digest', '--config', config, '--input', 'x'], io)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['remind', '--config', config, '--within-days', '7'], io),
    ).rejects.toMatchObject({ code: 'DELIVERY_REQUIRED' });
    await expect(
      runCli(['remind', '--config', config, '--unused-days', '3'], io),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    // The access report runs as the token holder too.
    await expect(
      runCli(['report', '--config', config, '--tenant', tenantId, '--within-days', 'x'], asRoot),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(
        ['config-export', '--config', config, '--tenant', tenantId, '--unused-days', '3'],
        asRoot,
      ),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await runCli(
      [
        'report',
        '--config',
        config,
        '--tenant',
        tenantId,
        '--within-days',
        '7',
        '--unused-days',
        '1',
      ],
      asRoot,
    );
    const accessReport = JSON.parse(output.at(-1)!);
    expect(accessReport).toMatchObject({
      withinMs: 7 * 86400000,
      unusedForMs: 86400000,
      omitted: [],
      identities: { expiring: [] },
      bindings: { expiring: [], activations: [], pendingRequests: 0 },
      credentials: { unused: [], expiring: [] },
    });
    expect(JSON.stringify(output)).not.toContain(session.token);
  });
});
