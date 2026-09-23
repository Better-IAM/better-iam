import { createRequire } from 'node:module';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  cliManifest,
  configFromEnv,
  createCli,
  defineCommand,
  loadConfig,
  main,
  runCli,
  type CliIO,
} from '@better-iam/cli';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'cli-dx-test-'));
  created.push(folder);
  return folder;
}
const secret = 'cli-dx-testing-secret-with-32-characters!';
const rootEnv = {
  BETTER_IAM_ROOT_EMAIL: 'root@example.test',
  BETTER_IAM_ROOT_NAME: 'Root',
  BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
};

function recorder(cwd?: string) {
  const output: string[] = [];
  return {
    output,
    io: (env: NodeJS.ProcessEnv = {}, more: Partial<CliIO> = {}): CliIO => ({
      out: (message) => output.push(message),
      env,
      ...(cwd ? { cwd } : {}),
      ...more,
    }),
    last: () => JSON.parse(output.at(-1)!),
  };
}

/** A factory configuration on its own SQLite file, plus project commands and CLI defaults. */
async function projectConfig(folder: string, extra = '') {
  const path = join(folder, 'better-iam.config.mjs');
  await writeFile(
    path,
    `import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { defineCommand } from '@better-iam/cli';
export default ({ command } = {}) => ({
  database: sqliteAdapter({ filename: ${JSON.stringify(join(folder, 'iam.db'))} }),
  secret: ${JSON.stringify(secret)},
  baseURL: 'http://localhost:3000',
  permissions: { actions: ['documents:read'] },
  authentication: { signUpEnabled: command === 'never' },
});
export const cli = { defaults: { 'echo-flags': { level: 5 }, '*': { format: 'compact' } } };
export const commands = [
  defineCommand({
    name: 'echo-flags',
    summary: 'Print the flags a project command received',
    target: 'config',
    flags: {
      level: { type: 'integer', env: 'ECHO_LEVEL', min: 0, max: 10, description: 'A level' },
      who: { type: 'string', required: true, description: 'A name' },
    },
    async run({ flags, iam, name }) {
      const instance = await iam();
      return { name, level: flags.level, who: flags.who, basePath: instance.endpoint.basePath };
    },
  }),
  defineCommand({
    name: 'rows',
    summary: 'Print two rows',
    run: () => ({ rows: [{ name: 'a', size: 1 }, { name: 'b', size: 2 }] }),
  }),
];
${extra}`,
  );
  return path;
}

/** Migrates and bootstraps a configuration, then signs root in with MFA (a separate connection). */
async function rootSession(config: string, filename: string) {
  const r = recorder();
  await runCli(['migrate', '--config', config], r.io(rootEnv));
  await runCli(['bootstrap', '--config', config], r.io(rootEnv));
  const tenantId = r.last().tenant.id as string;
  const iam = betterIam({
    database: sqliteAdapter({ filename }),
    secret,
    baseURL: 'http://localhost:3000',
    permissions: { actions: ['documents:read'] },
  });
  try {
    const challenge = await iam.api.auth.signIn({
      tenantId,
      email: rootEnv.BETTER_IAM_ROOT_EMAIL,
      password: rootEnv.BETTER_IAM_ROOT_PASSWORD,
    });
    if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
    const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
    const session = await iam.api.auth.confirmMfa({
      credential: { tenantId, challenge: challenge.challenge },
      code: authenticator.generate(enrollment.secret),
    });
    return { tenantId, token: session.token };
  } finally {
    await iam.store.close();
  }
}

describe('CLI developer experience', () => {
  it('describes every command in help, per-command help, and a JSON manifest', async () => {
    const r = recorder();
    await runCli(['help', '--json'], r.io());
    const manifest = r.last();
    expect(manifest).toEqual(JSON.parse(JSON.stringify(cliManifest())));
    const names = manifest.commands.map((command: { name: string }) => command.name);
    for (const name of [
      'init',
      'migrate',
      'whoami',
      'store-copy',
      'api',
      'login',
      'can',
      'completion',
    ])
      expect(names).toContain(name);
    for (const command of manifest.commands) {
      expect(command.usage).toMatch(new RegExp(`^better-iam ${command.name}\\b`));
      expect(command.summary.length).toBeGreaterThan(10);
    }
    const analyze = manifest.commands.find(
      (command: { name: string }) => command.name === 'analyze',
    );
    expect(analyze.flags).toContainEqual(
      expect.objectContaining({
        flag: '--tenant',
        value: 'TENANT_ID',
        optional: false,
        env: 'BETTER_IAM_TENANT',
      }),
    );
    expect(analyze.flags).toContainEqual(
      expect.objectContaining({ flag: '--fail-on', choices: ['high', 'medium', 'low'] }),
    );

    await runCli(['help', 'can'], r.io());
    const help = r.output.at(-1)!;
    expect(help).toContain('better-iam can - Check whether');
    expect(help).toContain('Examples');
    await runCli(['can', '--help'], r.io());
    expect(r.output.at(-1)).toBe(help);
    await runCli(['--version'], r.io());
    expect(r.output.at(-1)).toMatch(/^\d+\.\d+\.\d+/);

    await expect(runCli(['analyse'], r.io())).rejects.toMatchObject({
      code: 'INVALID_COMMAND',
      message: expect.stringContaining('Did you mean analyze?'),
    });
    await expect(runCli(['help', 'analyse'], r.io())).rejects.toMatchObject({
      code: 'INVALID_COMMAND',
    });
    await expect(runCli(['analyze', '--tenat', 'x'], r.io())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
      message: expect.stringContaining('Did you mean --tenant?'),
      hint: 'Run better-iam help analyze for its flags.',
    });
  });

  it('parses --flag=value, switches, and numbers the same way for every command', async () => {
    const r = recorder();
    await runCli(['secret', '--bytes=24'], r.io());
    expect(r.output.at(-1)).toMatch(/^[A-Za-z0-9_-]{32}$/);
    await runCli(['secret', '--env'], r.io());
    expect(r.output.at(-1)).toMatch(/^BETTER_IAM_SECRET=[A-Za-z0-9_-]{64}$/);
    for (const argv of [
      ['secret', '--bytes=10'],
      ['secret', '--bytes', 'many'],
      ['secret', '--env=maybe'],
      ['secret', 'extra'],
      ['secret', '--bytes', '30', '--bytes', '40'],
      ['secret', '-x'],
      ['sweep', '--limit'],
    ])
      await expect(runCli(argv, r.io()), argv.join(' ')).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
  });

  it('prints completion scripts for bash, zsh, fish, and PowerShell', async () => {
    const r = recorder();
    for (const shell of ['bash', 'zsh', 'fish', 'powershell']) {
      await runCli(['completion', shell], r.io());
      const script = r.output.at(-1)!;
      expect(script, shell).toContain('analyze');
      expect(script, shell).toContain(shell === 'fish' ? '-l fail-on' : '--fail-on');
      expect(script, shell).toContain('high');
    }
    expect(r.output[0]).toContain('complete -o default -F _better_iam better-iam');
    expect(r.output[1]).toContain('bashcompinit');
    expect(r.output[3]).toContain('Register-ArgumentCompleter');
    await expect(runCli(['completion', 'tcsh'], r.io())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(runCli(['completion'], r.io())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });

  it('scaffolds JavaScript and TypeScript configurations that the CLI loads by discovery', async () => {
    const folder = await directory();
    const r = recorder(folder);
    await runCli(['init'], r.io());
    const mjs = await readFile(join(folder, 'better-iam.config.mjs'), 'utf8');
    expect(mjs).toContain('defineConfig(');
    expect(mjs).toContain('export const cli');
    expect(mjs).toContain('export const commands');
    await runCli(['init', '--typescript', '--database', 'postgres'], r.io());
    const ts = await readFile(join(folder, 'better-iam.config.ts'), 'utf8');
    expect(ts).toContain('postgresAdapter');
    expect(ts).toContain('CliSettings');
    await expect(runCli(['init'], r.io())).rejects.toMatchObject({ code: 'CONFIG_EXISTS' });
    await expect(runCli(['init', '--database', 'mysql'], r.io())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });

    // The generated module runs as written (package names mapped to this workspace), found without --config.
    const project = join(folder, 'app');
    await mkdir(join(project, 'src', 'deep'), { recursive: true });
    await writeFile(
      join(project, 'better-iam.config.mjs'),
      mjs.replaceAll("'better-iam/", "'@better-iam/"),
    );
    const nested = recorder(join(project, 'src', 'deep'));
    const env = { BETTER_IAM_SECRET: secret, BETTER_IAM_DATABASE: join(project, 'iam.db') };
    await runCli(['migrate'], nested.io(env));
    expect(nested.output.at(-1)).toBe('Database and plugin migrations applied.');
    await runCli(['doctor'], nested.io(env));
    expect(nested.last()).toMatchObject({ database: 'connected', rootInitialized: false });

    const typed = join(folder, 'typed');
    await mkdir(typed);
    await writeFile(
      join(typed, 'better-iam.config.ts'),
      (await readFile(join(folder, 'better-iam.config.ts'), 'utf8'))
        .replaceAll("'better-iam/", "'@better-iam/")
        .replace(
          /postgresAdapter\(\{[^)]*\}\)/,
          `sqliteAdapter({ filename: ${JSON.stringify(join(typed, 'iam.db'))} })`,
        )
        .replace(
          /import \{ postgresAdapter \}[^\n]*/,
          "import { sqliteAdapter } from '@better-iam/adapter-sqlite';",
        ),
    );
    const typedRun = recorder(typed);
    await runCli(['migrate'], typedRun.io({ BETTER_IAM_SECRET: secret }));
    expect(typedRun.output.at(-1)).toBe('Database and plugin migrations applied.');
  });

  it('runs project commands with configuration defaults, environment variables, and output flags', async () => {
    const folder = await directory();
    const config = await projectConfig(folder);
    const r = recorder(folder);

    await runCli(['echo-flags', '--who', 'ada'], r.io());
    expect(r.output.at(-1)).not.toContain('\n');
    expect(r.last()).toEqual({ name: 'echo-flags', level: 5, who: 'ada', basePath: '/api/iam' });
    await runCli(['echo-flags', '--who', 'ada'], r.io({ ECHO_LEVEL: '7' }));
    expect(r.last().level).toBe(7);
    await runCli(
      ['echo-flags', '--who=ada', '--level=9', '--format', 'json'],
      r.io({ ECHO_LEVEL: '7' }),
    );
    expect(r.output.at(-1)).toContain('\n  "level": 9');
    await runCli(['echo-flags', '--who', 'ada', '--query', 'who'], r.io());
    expect(r.output.at(-1)).toBe('ada');
    await expect(runCli(['echo-flags'], r.io())).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['echo-flags', '--who', 'a', '--level', '11'], r.io()),
    ).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(
      runCli(['echo-flags', '--who', 'a'], r.io({ ECHO_LEVEL: 'high' })),
    ).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
      message: expect.stringContaining('ECHO_LEVEL'),
    });

    // Found through --config from elsewhere, BETTER_IAM_CONFIG, or discovery from a subdirectory.
    const elsewhere = recorder(await directory());
    await runCli(['rows', '--config', config, '--format', 'table'], elsewhere.io());
    expect(elsewhere.output.at(-1)).toBe('NAME  SIZE\na     1\nb     2');
    await runCli(['rows', '--query', 'rows[].name'], elsewhere.io({ BETTER_IAM_CONFIG: config }));
    expect(elsewhere.last()).toEqual(['a', 'b']);
    await mkdir(join(folder, 'sub'));
    await runCli(['echo-flags', '--who', 'x'], recorder(join(folder, 'sub')).io());
    await expect(runCli(['rows'], elsewhere.io())).rejects.toMatchObject({
      code: 'INVALID_COMMAND',
    });

    await runCli(['help', '--config', config], r.io());
    expect(r.output.at(-1)).toContain('echo-flags');
    await runCli(['help', 'echo-flags'], r.io());
    expect(r.output.at(-1)).toContain('--level N');
    await runCli(['completion', 'fish'], r.io());
    expect(r.output.at(-1)).toContain('-a echo-flags');
    await expect(runCli(['echo-flag', '--who', 'x'], r.io())).rejects.toMatchObject({
      message: expect.stringContaining('Did you mean echo-flags?'),
    });
  });

  it('configures a deployment from environment variables alone', async () => {
    const folder = await directory();
    const r = recorder(folder);
    const env = {
      BETTER_IAM_DATABASE_URL: `sqlite:${join(folder, 'env.db')}`,
      BETTER_IAM_SECRET: secret,
      ...rootEnv,
    };
    await runCli(['migrate'], r.io(env));
    await runCli(['bootstrap'], r.io(env));
    expect(r.last().identity.rootAdmin).toBe(true);
    await runCli(['doctor'], r.io(env));
    expect(r.last()).toMatchObject({ rootInitialized: true });
    await expect(runCli(['migrate'], r.io({}))).rejects.toMatchObject({ code: 'CONFIG_NOT_FOUND' });
    await expect(
      runCli(
        ['migrate'],
        r.io({ BETTER_IAM_DATABASE_URL: 'mysql://db', BETTER_IAM_SECRET: secret }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
    await expect(
      runCli(['migrate'], r.io({ BETTER_IAM_DATABASE_URL: `sqlite:${join(folder, 'x.db')}` })),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });

    const options = await configFromEnv({
      BETTER_IAM_DATABASE_URL: `sqlite:${join(folder, 'env.db')}`,
      BETTER_IAM_SECRET: secret,
      BETTER_IAM_TRUSTED_ORIGINS: 'https://a.test, https://b.test',
    });
    expect(options).toMatchObject({
      baseURL: 'http://localhost:3000',
      trustedOrigins: ['https://a.test', 'https://b.test'],
    });
    await options.database.close();

    const iam = await loadConfig({ cwd: folder, env });
    try {
      expect(await iam.store.find('tenants', { parentId: null })).toHaveLength(1);
    } finally {
      await iam.store.close();
    }
  });

  it('calls API routes in process and plans configuration written as code', async () => {
    const folder = await directory();
    const filename = join(folder, 'iam.db');
    const config = await projectConfig(folder);
    const { tenantId, token } = await rootSession(config, filename);
    const r = recorder(folder);
    const asRoot = { BETTER_IAM_TOKEN: token };

    await runCli(['api', 'auth.getSession', '--format', 'json'], r.io(asRoot));
    expect(r.last()).toMatchObject({ identity: { rootAdmin: true } });
    await runCli(
      ['api', 'roles.create', 'name=Auditor', 'permissions[]=documents:read', '--tenant', tenantId],
      r.io(asRoot),
    );
    expect(r.last()).toMatchObject({ name: 'Auditor', tenantId });
    await runCli(
      ['api', 'roles.list', '--query', '[].name'],
      r.io({ ...asRoot, BETTER_IAM_TENANT: tenantId }),
    );
    expect(r.last()).toContain('Auditor');
    await runCli(['api', '--list', 'config'], r.io(asRoot));
    expect(r.output.at(-1)).toContain('config.apply');

    // A tenant configuration module: a factory of the tenant and environment.
    const module = join(folder, 'tenant.config.mjs');
    await writeFile(
      module,
      `import { defineTenantConfig } from '@better-iam/server';
export default defineTenantConfig(({ tenantId, env }) => ({
  version: 1,
  roles: [{ name: env.ROLE_NAME ?? 'Reader', description: 'For ' + tenantId, permissions: ['documents:read'] }],
  groups: [{ name: 'Readers' }],
  bindings: [{ group: 'Readers', role: env.ROLE_NAME ?? 'Reader' }],
}));
`,
    );
    await runCli(['config-validate', '--input', module, '--tenant', tenantId], r.io());
    expect(r.last()).toEqual({
      valid: true,
      items: { roles: 1, groups: 1, bindings: 1 },
      warnings: [],
    });
    const env = { ...asRoot, ROLE_NAME: 'Viewer' };
    await runCli(['config-plan', '--tenant', tenantId, '--input', module], r.io(env));
    expect(r.last().summary).toEqual({ create: 3, update: 0, delete: 0, unchanged: 0 });
    await runCli(['config-apply', '--tenant', tenantId, '--input', module], r.io(env));
    expect(r.last()).toMatchObject({ applied: true });

    // Exported back as typed code that plans as unchanged.
    for (const name of ['exported.config.ts', 'exported.config.mjs']) {
      const output = join(folder, name);
      await runCli(['config-export', '--tenant', tenantId, '--output', output], r.io(asRoot));
      const text = await readFile(output, 'utf8');
      expect(text).toContain(
        name.endsWith('.ts')
          ? 'defineTenantConfig('
          : "@type {import('better-iam/server').TenantConfig}",
      );
      await writeFile(output, text.replaceAll("'better-iam/", "'@better-iam/"));
      await runCli(
        ['config-plan', '--tenant', tenantId, '--input', output, '--fail-on-drift'],
        r.io(asRoot),
      );
      expect(r.last().summary).toMatchObject({ create: 0, update: 0, delete: 0 });
    }

    // Offline validation: shape errors fail, unresolved names warn (and fail with --strict).
    const loose = join(folder, 'loose.json');
    await writeFile(
      loose,
      JSON.stringify({
        version: 1,
        roles: [{ name: 'A', policies: ['Missing'], permissions: ['documents:read'] }],
        bindings: [{ group: 'Nobody', role: 'A' }],
      }),
    );
    await runCli(['config-validate', '--input', loose], r.io());
    expect(r.last().warnings).toEqual([
      'Role "A" names policy "Missing", which this file does not define',
      'Binding Nobody -> A names group "Nobody", which this file does not define',
    ]);
    await expect(
      runCli(['config-validate', '--input', loose, '--strict'], r.io()),
    ).rejects.toMatchObject({
      code: 'CONFIG_WARNINGS',
    });
    await writeFile(loose, JSON.stringify({ version: 2 }));
    await expect(runCli(['config-validate', '--input', loose], r.io())).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('keeps local saved sessions with their configuration and orders flag sources', async () => {
    const folder = await directory();
    const filename = join(folder, 'iam.db');
    const config = await projectConfig(
      folder,
      `export const tenantProbe = defineCommand({
  name: 'show-tenant',
  summary: 'Print the tenant a token command resolved',
  target: 'token',
  flags: { tenant: { type: 'string', env: 'BETTER_IAM_TENANT', profile: 'tenantId', description: 'Tenant' } },
  run: ({ flags }) => ({ tenant: flags.tenant ?? null }),
});
commands.push(tenantProbe);
cli.defaults['show-tenant'] = { tenant: 'from-defaults' };`,
    );
    const { tenantId, token } = await rootSession(config, filename);
    const credentials = { BETTER_IAM_CREDENTIALS: join(folder, 'credentials.json') };
    const elsewhere = recorder(await directory());

    // Saved through the configuration: later commands use it from anywhere, without --config.
    await runCli(
      ['login', '--with-token', '--config', config],
      elsewhere.io(credentials, {
        stdin: async () => token,
      }),
    );
    expect(elsewhere.last()).toMatchObject({ profile: 'default', config, tenantId });
    await runCli(['whoami', '--format', 'json'], elsewhere.io(credentials));
    expect(elsewhere.last()).toMatchObject({ tenantId });
    // Another configuration is another deployment.
    const other = await projectConfig(await directory());
    await expect(
      runCli(['whoami', '--config', other], elsewhere.io(credentials)),
    ).rejects.toMatchObject({
      code: 'MISSING_ENV',
    });
    // An explicit --config beats BETTER_IAM_URL; both from the environment is ambiguous.
    await runCli(
      ['whoami', '--config', config],
      elsewhere.io({ ...credentials, BETTER_IAM_URL: 'http://localhost:9' }),
    );
    await expect(
      runCli(
        ['whoami'],
        elsewhere.io({
          ...credentials,
          BETTER_IAM_URL: 'http://localhost:9',
          BETTER_IAM_CONFIG: config,
        }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });

    // Flag sources: command line, then environment, then configuration defaults, then the saved session.
    const r = recorder(folder);
    await runCli(['show-tenant'], r.io(credentials));
    expect(r.last()).toEqual({ tenant: 'from-defaults' });
    await runCli(['show-tenant'], r.io({ ...credentials, BETTER_IAM_TENANT: 'from-env' }));
    expect(r.last()).toEqual({ tenant: 'from-env' });
    await runCli(
      ['show-tenant', '--tenant', 'from-flag'],
      r.io({ ...credentials, BETTER_IAM_TENANT: 'from-env' }),
    );
    expect(r.last()).toEqual({ tenant: 'from-flag' });
    // Without defaults for it, --tenant falls back to the saved session's tenant.
    await runCli(['api', 'roles.create', 'name=Probe', '--query', 'tenantId'], r.io(credentials));
    expect(r.output.at(-1)).toBe(tenantId);

    await runCli(['logout'], elsewhere.io(credentials));
    expect(elsewhere.last()).toEqual({ profile: 'default', revoked: true, forgotten: true });
    await expect(
      runCli(['whoami', '--config', config], elsewhere.io({ BETTER_IAM_TOKEN: token })),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('signs sessions of environment-only deployments out through the same environment', async () => {
    const folder = await directory();
    const filename = join(folder, 'env.db');
    const env = {
      BETTER_IAM_DATABASE_URL: `sqlite:${filename}`,
      BETTER_IAM_SECRET: secret,
      ...rootEnv,
    };
    const r = recorder(folder);
    await runCli(['migrate'], r.io(env));
    await runCli(['bootstrap'], r.io(env));
    const tenantId = r.last().tenant.id as string;
    const iam = betterIam({
      database: sqliteAdapter({ filename }),
      secret,
      baseURL: 'http://localhost:3000',
    });
    let token: string;
    try {
      const challenge = await iam.api.auth.signIn({
        tenantId,
        email: rootEnv.BETTER_IAM_ROOT_EMAIL,
        password: rootEnv.BETTER_IAM_ROOT_PASSWORD,
      });
      if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
      const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
      token = (
        await iam.api.auth.confirmMfa({
          credential: { tenantId, challenge: challenge.challenge },
          code: authenticator.generate(enrollment.secret),
        })
      ).token;
    } finally {
      await iam.store.close();
    }
    const saved = { ...env, BETTER_IAM_CREDENTIALS: join(folder, 'credentials.json') };
    await runCli(['login', '--with-token'], r.io(saved, { stdin: async () => token }));
    expect(
      JSON.parse(await readFile(saved.BETTER_IAM_CREDENTIALS, 'utf8')).profiles.default,
    ).toMatchObject({
      envConfig: true,
    });
    await runCli(['whoami', '--format', 'json'], r.io(saved));
    expect(r.last()).toMatchObject({ tenantId });
    await runCli(['logout'], r.io(saved));
    expect(r.last()).toMatchObject({ revoked: true });
  });

  it('completes flag values in bash before flag names', async () => {
    const r = recorder();
    await runCli(['completion', 'bash'], r.io());
    const script = r.output.at(-1)!;
    const analyze = script.slice(script.indexOf('    analyze)'));
    expect(
      analyze.indexOf("--fail-on) COMPREPLY=( $(compgen -W 'high medium low'"),
    ).toBeGreaterThan(0);
    expect(analyze.indexOf('--fail-on) COMPREPLY')).toBeLessThan(analyze.indexOf('-*) COMPREPLY'));
    expect(script).not.toContain('*) return ;;');
  });

  it('builds project CLIs from code and reports failures with exit codes', async () => {
    const hello = defineCommand({
      name: 'hello',
      summary: 'Greet someone by name',
      args: [{ name: 'who', description: 'Who to greet', required: true }],
      flags: { shout: { type: 'boolean', description: 'Upper case' } },
      output: 'text',
      run: ({ args, flags }) =>
        flags.shout ? `HELLO ${args[0]!.toUpperCase()}` : `hello ${args[0]}`,
    });
    const only = createCli({ builtins: false, commands: [hello], version: '9.9.9' });
    const r = recorder();
    await only.run(['hello', 'world', '--shout'], r.io());
    expect(r.output.at(-1)).toBe('HELLO WORLD');
    expect(only.manifest().commands.map((command) => command.name)).toEqual(['hello']);
    expect(only.help()).not.toContain('migrate');
    expect(only.help('hello')).toContain('better-iam hello WHO [--shout]');
    await expect(only.run(['migrate'], r.io())).rejects.toMatchObject({ code: 'INVALID_COMMAND' });
    expect(createCli({ commands: [hello] }).commands.length).toBe(
      cliManifest().commands.length + 1,
    );

    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    expect(await main(['analyse'])).toBe(2);
    expect(errors.mock.calls.flat().join('\n')).toContain(
      'INVALID_COMMAND: Unknown command: analyse',
    );
    expect(await main(['migrate', '--config', join(await directory(), 'missing.mjs')])).toBe(1);
    expect(errors.mock.calls.flat().join('\n')).toContain('Hint: Run better-iam init');
    expect(await main(['hello', 'x'], only)).toBe(0);
  });
});
