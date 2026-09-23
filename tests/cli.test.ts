import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true });
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'cli-test-'));
  created.push(folder);
  return folder;
}
describe('deployment CLI', () => {
  it('scaffolds configuration without overwriting an existing file', async () => {
    const config = join(await directory(), 'better-iam.config.mjs');
    const lines: string[] = [];
    await runCli(['init', '--config', config], { out: (line) => lines.push(line), env: {} });
    expect(await readFile(config, 'utf8')).toContain('BETTER_IAM_SECRET');
    await expect(
      runCli(['init', '--config', config], { out: () => {}, env: {} }),
    ).rejects.toMatchObject({ code: 'CONFIG_EXISTS' });
    expect(lines).toHaveLength(1);
  });
  it('migrates, bootstraps, diagnoses and recovers through trusted configuration', async () => {
    const folder = await directory(),
      config = join(folder, 'better-iam.config.mjs'),
      output: string[] = [];
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(join(folder, 'iam.db'))}}),secret:'cli-testing-secret-with-32-characters',baseURL:'http://localhost:3000'});\n`,
    );
    const io = {
      out: (message: string) => output.push(message),
      env: {
        BETTER_IAM_ROOT_EMAIL: 'root@example.test',
        BETTER_IAM_ROOT_NAME: 'Root',
        BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
      },
    };
    await runCli(['migrate', '--config', config], io);
    await runCli(['bootstrap', '--config', config], io);
    const bootstrap = JSON.parse(output.at(-1)!);
    expect(bootstrap.mfaEnrollmentRequired).toBe(true);
    expect(JSON.stringify(output)).not.toContain(io.env.BETTER_IAM_ROOT_PASSWORD);
    await runCli(['doctor', '--config', config], io);
    expect(JSON.parse(output.at(-1)!).rootInitialized).toBe(true);
    await expect(runCli(['bootstrap', '--config', config], io)).rejects.toMatchObject({
      code: 'ALREADY_INITIALIZED',
    });
    await runCli(['recover-root', '--config', config], {
      ...io,
      env: { ...io.env, BETTER_IAM_ROOT_EMAIL: 'recovery@example.test' },
    });
    expect(JSON.parse(output.at(-1)!).identity.rootAdmin).toBe(true);
    await runCli(['outbox', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({ delivered: 0, failed: 0, abandoned: 0 });
    await runCli(['purge', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({
      purgedTenants: [],
      deletedRecords: 0,
      expiredBindings: 0,
      expiredRequests: 0,
      expiredIdentities: 0,
      expiredActivations: 0,
      expiredMemberships: 0,
      expiredAssignments: 0,
    });
    await runCli(['purge', '--config', config, '--retention-days', '0'], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({
      purgedTenants: [],
      deletedRecords: 0,
      expiredBindings: 0,
      expiredRequests: 0,
      expiredIdentities: 0,
      expiredActivations: 0,
      expiredMemberships: 0,
      expiredAssignments: 0,
    });
    // Audit chain operations read storage directly and never record events themselves.
    const tenantId = bootstrap.tenant.id as string;
    await runCli(['audit-verify', '--config', config, '--tenant', tenantId], io);
    const verification = JSON.parse(output.at(-1)!);
    expect(verification).toMatchObject({ tenantId, valid: true, first: 1, unchained: 0 });
    expect(verification.checked).toBeGreaterThanOrEqual(3);
    const exportPath = join(folder, 'audit.jsonl');
    await runCli(
      ['audit-export', '--config', config, '--tenant', tenantId, '--output', exportPath],
      io,
    );
    const exported = JSON.parse(output.at(-1)!);
    expect(exported).toMatchObject({ tenantId, count: verification.checked, firstSequence: 1 });
    const lines = (await readFile(exportPath, 'utf8')).trim().split('\n');
    expect(lines).toHaveLength(verification.checked);
    expect(JSON.parse(lines[0]!).sequence).toBe(1);
    await runCli(['doctor', '--config', config], io);
    expect(JSON.parse(output.at(-1)!).auditChains).toBe(1);
    // Pruning after archiving keeps the chain verifiable from the checkpoint.
    await runCli(['audit-prune', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({ deleted: 0 });
    await runCli(
      ['audit-prune', '--config', config, '--tenant', tenantId, '--retention-days', '0'],
      io,
    );
    const pruned = JSON.parse(output.at(-1)!);
    expect(pruned.deleted).toBe(verification.checked);
    await runCli(['audit-verify', '--config', config, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      valid: true,
      checked: 1,
      first: verification.checked + 1,
    });
    await expect(
      runCli(
        ['audit-export', '--config', config, '--tenant', tenantId, '--output', exportPath],
        io,
      ),
    ).rejects.toThrow();
    await expect(runCli(['audit-verify', '--config', config], io)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['purge', '--config', config, '--tenant', tenantId], io),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});
