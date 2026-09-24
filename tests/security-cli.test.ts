import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { formatResult, runCli, type CliIO } from '@better-iam/cli';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { requestBody } from '../packages/cli/src/commands/api.js';

/**
 * The CLI: help and shell completion never run a configuration they merely found, CI gates fail on a chain that
 * proves nothing, destructive retention flags ignore shared defaults, and server text cannot drive the terminal.
 */

const secret = 'cli-security-testing-secret-with-32-characters';
const rootEnv = {
  BETTER_IAM_ROOT_EMAIL: 'root@example.test',
  BETTER_IAM_ROOT_NAME: 'Root',
  BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
};
const folders: string[] = [];
afterEach(async () => {
  for (const folder of folders.splice(0))
    await rm(folder, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});
async function folder(prefix: string) {
  const created = await mkdtemp(join(tmpdir(), `better-iam-${prefix}`));
  folders.push(created);
  return created;
}
function recorder(cwd: string, env: NodeJS.ProcessEnv) {
  const output: string[] = [];
  const io: CliIO = { out: (message) => output.push(message), err: () => {}, env, cwd };
  return { io, output, last: () => JSON.parse(output.at(-1)!) };
}
const exists = (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );

describe('configuration discovery', () => {
  for (const argv of [['help'], ['--help'], ['help', 'login'], ['completion', 'bash']])
    it(`better-iam ${argv.join(' ')} never imports a configuration it found`, async () => {
      const top = await folder('discover-');
      const marker = join(top, 'marker.txt').replaceAll('\\', '/');
      await writeFile(
        join(top, 'better-iam.config.mjs'),
        `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'ran');\nexport const commands = [];\n`,
      );
      const deep = join(top, 'a', 'b');
      await mkdir(deep, { recursive: true });
      await runCli(argv, recorder(deep, {}).io).catch(() => undefined);
      expect(await exists(marker)).toBe(false);
    });

  it('stops at the repository root', async () => {
    const top = await folder('boundary-');
    const marker = join(top, 'marker.txt').replaceAll('\\', '/');
    await writeFile(
      join(top, 'better-iam.config.mjs'),
      `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'ran');\nexport default {};\n`,
    );
    const repository = join(top, 'repo');
    await mkdir(join(repository, '.git'), { recursive: true });
    await runCli(['migrate'], recorder(repository, {}).io).catch(() => undefined);
    expect(await exists(marker)).toBe(false);
  });
});

describe('audit gates', () => {
  it('fail on an unknown tenant, a wiped chain, and an empty archive', async () => {
    const directory = await folder('audit-');
    const database = join(directory, 'iam.db');
    const env = {
      BETTER_IAM_DATABASE_URL: `sqlite:${database}`,
      BETTER_IAM_SECRET: secret,
      ...rootEnv,
    };
    const r = recorder(directory, env);
    await runCli(['migrate'], r.io);
    await runCli(['bootstrap'], r.io);
    const tenantId = r.last().tenant.id as string;
    await expect(runCli(['audit-verify', '--tenant', 'no-such-tenant'], r.io)).rejects.toMatchObject(
      { code: 'NOT_FOUND' },
    );
    await runCli(['audit-verify', '--tenant', tenantId], r.io);
    expect(r.last().valid).toBe(true);
    const iam = betterIam({
      database: sqliteAdapter({ filename: database }),
      secret,
      baseURL: 'http://localhost:3000',
    });
    try {
      await iam.store.transaction(async (tx) => {
        for (const event of await tx.find('audit', { tenantId })) await tx.delete('audit', event.id);
      });
    } finally {
      await iam.store.close();
    }
    await expect(runCli(['audit-verify', '--tenant', tenantId], r.io)).rejects.toMatchObject({
      code: 'AUDIT_CHAIN_BROKEN',
    });
    const archive = await folder('archive-');
    await mkdir(join(archive, 'ten_1'));
    await expect(
      runCli(['audit-verify-archive', '--directory', archive, '--tenant', 'ten_1'], r.io),
    ).rejects.toMatchObject({ code: 'AUDIT_ARCHIVE_INVALID' });
  });

  it("never lets a shared '*' default shorten audit-prune retention", async () => {
    const directory = await folder('defaults-');
    await writeFile(
      join(directory, 'better-iam.config.mjs'),
      `export default { api: {}, initialize() {}, pruneAudit(input) { return input; }, store: { close: async () => {} } };\nexport const cli = { defaults: { '*': { 'retention-days': 7 } } };\n`,
    );
    const r = recorder(directory, {});
    await runCli(['audit-prune', '--tenant', 't1'], r.io);
    expect(r.last().retentionMs).toBe(365 * 86400000);
  });
});

describe('output and input', () => {
  it('shows terminal control sequences from server data as replacement characters', () => {
    const evil = 'Mallory\u001b]52;c;cHduZWQ=\u0007\u001b[2K';
    expect(formatResult({ rows: [{ name: evil }] }, 'table')).not.toContain('\u001b');
    expect(formatResult({ name: evil }, 'json', 'name')).not.toContain('\u001b');
    // JSON output escapes them already.
    expect(formatResult({ name: evil }, 'json')).not.toContain('\u001b');
  });

  it('sends a literal @ value when it is escaped', async () => {
    const directory = await folder('api-');
    await writeFile(join(directory, 'secret.txt'), 'TOP-SECRET');
    const context = {
      io: { out: () => {}, env: {} },
      path: (value: string) => join(directory, value),
    } as unknown as Parameters<typeof requestBody>[0];
    expect(await requestBody(context, undefined, ['displayName=\\@secret.txt'])).toEqual({
      displayName: '@secret.txt',
    });
  });
});
