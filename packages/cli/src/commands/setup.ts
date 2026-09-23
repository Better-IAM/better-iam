import { access, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { IamError, type AuditChainHead } from '@better-iam/core';
import { CliError } from '../errors.js';
import { defineCommand } from '../framework.js';

type Database = 'sqlite' | 'postgres' | 'libsql';

const adapters: Record<Database, { imports: string; factory: string }> = {
  sqlite: {
    imports: `import { sqliteAdapter } from 'better-iam/adapter-sqlite';`,
    factory: `sqliteAdapter({ filename: env.BETTER_IAM_DATABASE ?? './better-iam.db' })`,
  },
  libsql: {
    imports: `import { libsqlAdapter } from 'better-iam/adapter-libsql';`,
    factory: `libsqlAdapter({ url: env.BETTER_IAM_DATABASE_URL ?? 'file:./better-iam.db', authToken: env.BETTER_IAM_DATABASE_TOKEN })`,
  },
  postgres: {
    imports: `import { postgresAdapter } from 'better-iam/adapter-postgres';`,
    factory: `postgresAdapter({ connectionString: env.DATABASE_URL })`,
  },
};

/** The starter configuration `init` writes: a side-effect-free factory, CLI defaults, and a slot for project commands. */
export function configTemplate(database: Database, typescript: boolean): string {
  const { imports, factory } = adapters[database];
  const cliType = typescript ? `: CliSettings` : '';
  const commandsType = typescript ? `: CommandSpec<any>[]` : '';
  return `// Better IAM deployment configuration, loaded by the better-iam CLI and by your server:
//   import config from './better-iam.config${typescript ? '' : '.mjs'}';
//   const iam = betterIam(await configOptions(config));   // both from 'better-iam/server'
${typescript ? `import type { CliSettings, CommandSpec } from 'better-iam/cli';\n` : ''}import { defineConfig } from 'better-iam/server';
${imports}

// A factory keeps importing this file free of side effects (the CLI imports it for help and flag defaults).
// It receives { command, env, cwd } when the CLI calls it, so settings can depend on the command.
const createOptions = defineConfig(({ env = process.env } = {}) => ({
  database: ${factory},
  baseURL: env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
  // At least 32 random characters; generate one with: better-iam secret
  secret: env.BETTER_IAM_SECRET${typescript ? ' ?? ""' : ''},
  // During a secret rotation, the old value(s), comma-separated (see the deployment guide).
  previousSecrets: env.BETTER_IAM_PREVIOUS_SECRETS?.split(',').filter(Boolean),
  authentication: {
    // Add sendEmail/sendSms callbacks before enabling delivery-dependent features.
    signUpEnabled: false,
  },
  // Add plugins: [createProjectsPlugin()] from 'better-iam/projects' to serve the projects actions.
  permissions: {
    mode: 'catalog', // 'tenant-defined' lets organizations register their own resource types and actions
    actions: ['projects:read', 'projects:write'],
    // Declare resource types to validate policies and describe attributes; managed types are registered with IAM.
    resourceTypes: {
      workspace: {
        managed: true,
        actions: ['workspaces:read', 'workspaces:manage'],
        attributes: { archived: 'boolean' },
      },
    },
  },
}));
export default createOptions;

// Defaults for CLI flags when neither the flag nor its environment variable is set: per command, or '*' for every
// command that has the flag (better-iam help <command> lists them).
export const cli${cliType} = {
  defaults: {
    sweep: { 'retention-days': 30 },
  },
};

// Project commands: \`better-iam <name>\` runs them with the same flag parsing, help, and output as the built-in ones.
// import { defineCommand } from 'better-iam/cli';
export const commands${commandsType} = [];
`;
}

export const setupCommands = [
  defineCommand({
    name: 'init',
    group: 'Setup',
    summary: 'Write a starter configuration file for SQLite, PostgreSQL, or libSQL',
    description:
      'init writes a starter better-iam.config.mjs (or better-iam.config.ts with --typescript): a configuration factory for the chosen database that reads the secret and URLs from the environment, CLI flag defaults, and an empty list of project commands. It never overwrites an existing file.',
    usage:
      'better-iam init [--config better-iam.config.mjs] [--database sqlite|postgres|libsql] [--typescript]',
    output: 'text',
    flags: {
      config: { type: 'string', value: 'PATH', description: 'Where to write the configuration' },
      database: {
        type: 'string',
        choices: ['sqlite', 'postgres', 'libsql'],
        default: 'sqlite',
        description: 'Database adapter to configure',
      },
      typescript: { type: 'boolean', description: 'Write a typed better-iam.config.ts' },
    },
    examples: ['better-iam init', 'better-iam init --database postgres --typescript'],
    async run({ flags, path, io }) {
      const target = path(
        flags.config ?? (flags.typescript ? 'better-iam.config.ts' : 'better-iam.config.mjs'),
      );
      try {
        await access(target);
        throw new IamError('CONFIG_EXISTS', 'Configuration already exists; it was not overwritten');
      } catch (error) {
        if (error instanceof IamError) throw error;
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      await writeFile(
        target,
        configTemplate((flags.database ?? 'sqlite') as Database, flags.typescript),
        { flag: 'wx' },
      );
      io.out(
        `Created ${target}. Set BETTER_IAM_SECRET to a stable high-entropy secret (at least 32 characters; better-iam secret prints one), then run migrate.`,
      );
    },
  }),
  defineCommand({
    name: 'migrate',
    group: 'Setup',
    summary: 'Create or upgrade the database schema and apply plugin migrations',
    description:
      'migrate creates or upgrades the database schema and applies plugin migrations. Run it on every deploy before the application starts.',
    target: 'config',
    output: 'text',
    async run({ iam }) {
      await (await iam()).initialize();
      return 'Database and plugin migrations applied.';
    },
  }),
  defineCommand({
    name: 'bootstrap',
    group: 'Setup',
    summary: 'Create the root administrator from environment variables',
    description:
      'bootstrap creates the root administrator from BETTER_IAM_ROOT_EMAIL, BETTER_IAM_ROOT_NAME, and BETTER_IAM_ROOT_PASSWORD (secrets are never accepted in command-line arguments). The root must enroll MFA before use.',
    target: 'config',
    async run({ iam, env }) {
      return (await iam()).bootstrap(rootInput(env));
    },
  }),
  defineCommand({
    name: 'recover-root',
    group: 'Setup',
    summary: 'Create a new root administrator when every root credential is lost',
    description:
      'recover-root creates a new root administrator from the same environment variables as bootstrap, for when every root credential is lost; the action is audited as root:recover.',
    target: 'config',
    async run({ iam, env }) {
      return (await iam()).recoverRoot(rootInput(env));
    },
  }),
  defineCommand({
    name: 'doctor',
    group: 'Setup',
    summary: 'Check the database, schema, secrets, transports, and scheduled jobs',
    description:
      'doctor connects to the database and lists findings (schema behind, not bootstrapped, weak secret, risky durability, missing email transport, jobs that are not running); --strict exits non-zero when any error or warning is found; pass the --retention-days your sweep uses so its backlog is judged the same way.',
    target: 'config',
    flags: {
      strict: { type: 'boolean', description: 'Exit non-zero when any error or warning is found' },
      'retention-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        description: 'Delivery retention your sweep uses, to judge its backlog the same way',
      },
    },
    async run({ iam, flags, print }) {
      const instance = await iam();
      // Schema, durability, secrets, transports, and scheduled jobs (`iam.selfCheck()`); first,
      // so a database without the IAM schema is reported instead of failing the reads below.
      const check = await instance.selfCheck(
        flags['retention-days'] !== undefined
          ? { deliveryRetentionMs: flags['retention-days'] * 86400000 }
          : {},
      );
      const schema = check.storage === null || check.storage.schemaVersion !== null;
      const roots = schema ? await instance.store.find('tenants', { parentId: null }) : [];
      const chains = schema ? await instance.store.find<AuditChainHead>('auditChains') : [];
      print({
        node: process.versions.node,
        database: 'connected',
        rootInitialized: roots.length === 1,
        rootCount: roots.length,
        auditChains: chains.length,
        auditEvents: chains.reduce((sum, chain) => sum + chain.sequence, 0),
        // Adapter, schema version, applied migrations, record counts, and durability settings.
        storage: check.storage,
        ok: check.ok,
        findings: check.findings,
      });
      const serious = check.findings.filter((finding) => finding.severity !== 'info');
      if (flags.strict && serious.length)
        throw new IamError(
          'DOCTOR_FINDINGS',
          `${serious.length} finding(s): ${serious.map((finding) => finding.check).join(', ')}`,
        );
    },
  }),
  defineCommand({
    name: 'secret',
    group: 'Setup',
    summary: 'Print a new random secret for BETTER_IAM_SECRET',
    description:
      'secret prints a new random value for BETTER_IAM_SECRET (64 URL-safe characters by default) from the operating system random generator; --env prints it as a BETTER_IAM_SECRET= line for a .env file. It reads no configuration and stores nothing.',
    output: 'text',
    flags: {
      bytes: {
        type: 'integer',
        min: 24,
        max: 256,
        default: 48,
        description: 'Random bytes (the secret is their base64url form)',
      },
      env: { type: 'boolean', description: 'Print BETTER_IAM_SECRET=value' },
    },
    examples: ['better-iam secret --env >> .env'],
    run({ flags }) {
      const value = randomBytes(flags.bytes ?? 48).toString('base64url');
      return flags.env ? `BETTER_IAM_SECRET=${value}` : value;
    },
  }),
];

function rootInput(env: NodeJS.ProcessEnv): { email: string; name: string; password: string } {
  const email = env.BETTER_IAM_ROOT_EMAIL,
    name = env.BETTER_IAM_ROOT_NAME ?? 'Root administrator',
    password = env.BETTER_IAM_ROOT_PASSWORD;
  if (!email || !password)
    throw new CliError(
      'MISSING_ENV',
      'Set BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD',
      'The password is read from the environment only, never from a flag.',
    );
  return { email, name, password };
}
