import { createRequire } from 'node:module';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { secretEnvName } from '../packages/cli/src/commands/vault.js';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { DeliveryMessage } from '@better-iam/auth';

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
const secret = 'vault-cli-testing-secret-with-32-characters';

/** A migrated deployment with one organization, its owner's token, and a CLI io bound to it. */
async function deployment() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'vault-cli-test-'));
  created.push(folder);
  const config = join(folder, 'better-iam.config.mjs');
  const filename = join(folder, 'iam.db');
  const output: string[] = [];
  await writeFile(
    config,
    `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(filename)}}),secret:${JSON.stringify(secret)},baseURL:'http://localhost:3000'});\n`,
  );
  const setup = {
    out: (message: string) => output.push(message),
    env: {
      BETTER_IAM_ROOT_EMAIL: 'root@example.test',
      BETTER_IAM_ROOT_NAME: 'Root',
      BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
    } as NodeJS.ProcessEnv,
  };
  await runCli(['migrate', '--config', config], setup);
  await runCli(['bootstrap', '--config', config], setup);
  const rootId = JSON.parse(output.at(-1)!).tenant.id as string;
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database: sqliteAdapter({ filename }),
    secret,
    baseURL: 'http://localhost:3000',
    authentication: { sendEmail: async (message) => void inbox.push(message) },
  });
  try {
    const challenge = await iam.api.auth.signIn({
      tenantId: rootId,
      email: 'root@example.test',
      password: 'a strong cli root password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
    const enrollment = await iam.api.auth.beginMfa({ tenantId: rootId, challenge: challenge.challenge });
    const root = {
      token: (
        await iam.api.auth.confirmMfa({
          credential: { tenantId: rootId, challenge: challenge.challenge },
          code: authenticator.generate(enrollment.secret),
        })
      ).token,
    };
    const org = await iam.api.tenants.create(root, {
      parentId: rootId,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    });
    await iam.auth.dispatchOutbox();
    const invitation = inbox.find((message) => message.template === 'owner-invitation')!;
    const owner = await iam.api.tenants.acceptInvitation({
      tenantId: org.tenant.id,
      token: invitation.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected MFA');
    const tenantId = org.tenant.id;
    await iam.api.vault.create({ token: owner.token }, {
      tenantId,
      name: 'app/db-password',
      value: 'the-database-password',
    });
    await iam.api.vault.create({ token: owner.token }, {
      tenantId,
      name: 'app/smtp',
      format: 'json',
      fields: { host: 'smtp.acme.test', password: 'mail-password' },
    });
    await iam.api.vault.create({ token: owner.token }, {
      tenantId,
      name: 'app/signing-key',
      value: 'k1',
      rotation: { intervalDays: 1, generator: { length: 16 } },
    });
    const io = (stdin?: string) => ({
      out: (message: string) => output.push(message),
      env: { BETTER_IAM_TOKEN: owner.token, BETTER_IAM_TENANT: tenantId, KEEP_ME: 'yes' } as NodeJS.ProcessEnv,
      ...(stdin !== undefined ? { stdin: async () => stdin } : {}),
    });
    return { folder, config, output, io, tenantId };
  } finally {
    await iam.store.close();
  }
}

describe('vault CLI', () => {
  it('names environment variables after secret paths', () => {
    expect(secretEnvName('prod/app/db-password', 'prod/app/')).toBe('DB_PASSWORD');
    expect(secretEnvName('prod/app/v2.api-key', 'prod/')).toBe('APP_V2_API_KEY');
    expect(secretEnvName('prod/app/1st', 'prod/app/')).toBe('_1ST');
  });

  it('puts, gets and runs a command with secrets in its environment', async () => {
    const d = await deployment();
    await runCli(['vault-put', 'app/db-password', '--config', d.config], d.io('rotated-by-cli\n'));
    expect(JSON.parse(d.output.at(-1)!)).toMatchObject({ version: 2, stages: ['current'] });
    await runCli(['vault-get', 'app/db-password', '--config', d.config], d.io());
    expect(d.output.at(-1)).toBe('rotated-by-cli');
    await runCli(['vault-get', 'app/smtp', '--field', 'host', '--config', d.config], d.io());
    expect(d.output.at(-1)).toBe('smtp.acme.test');

    const dump = join(d.folder, 'env.json');
    const script = `require('fs').writeFileSync(${JSON.stringify(dump)}, JSON.stringify(process.env))`;
    await runCli(
      [
        'vault-run',
        '--config',
        d.config,
        '--env',
        'DATABASE_PASSWORD=app/db-password,MAIL_HOST=app/smtp#host',
        '--prefix',
        'app/',
        '--',
        process.execPath,
        '-e',
        script,
      ],
      d.io(),
    );
    const env = JSON.parse(await readFile(dump, 'utf8')) as Record<string, string>;
    expect(env).toMatchObject({
      DATABASE_PASSWORD: 'rotated-by-cli',
      MAIL_HOST: 'smtp.acme.test',
      DB_PASSWORD: 'rotated-by-cli',
      SMTP_HOST: 'smtp.acme.test',
      SMTP_PASSWORD: 'mail-password',
      SIGNING_KEY: 'k1',
      KEEP_ME: 'yes',
    });
    // The IAM token does not travel to the child.
    expect(env.BETTER_IAM_TOKEN).toBeUndefined();

    // The command's exit status comes back.
    await expect(
      runCli(
        ['vault-run', '--config', d.config, '--env', 'X=app/db-password', '--', process.execPath, '-e', 'process.exit(3)'],
        d.io(),
      ),
    ).rejects.toMatchObject({ code: 'COMMAND_FAILED', exitStatus: 3 });
    await expect(
      runCli(['vault-run', '--config', d.config, '--', process.execPath], d.io()),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['vault-run', '--config', d.config, '--env', '1BAD=app/x', '--', process.execPath], d.io()),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('runs the vault jobs', async () => {
    const d = await deployment();
    await runCli(['vault-rotate-due', '--config', d.config], d.io());
    expect(JSON.parse(d.output.at(-1)!)).toEqual({ rotated: [], failed: [], reminded: [] });
    await runCli(['vault-expire-leases', '--config', d.config], d.io());
    expect(JSON.parse(d.output.at(-1)!)).toMatchObject({ expired: 0 });
    await runCli(['vault-purge-deleted', '--config', d.config], d.io());
    expect(JSON.parse(d.output.at(-1)!)).toEqual({ purged: 0 });
  });
});
