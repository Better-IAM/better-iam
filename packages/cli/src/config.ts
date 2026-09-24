import { access, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IamError } from '@better-iam/core';
import { betterIam, type BetterIam, type BetterIamOptions } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { postgresAdapter } from '@better-iam/adapter-postgres';
import { CliError } from './errors.js';
import type { CommandSpec } from './framework.js';

/**
 * Configuration file names the CLI looks for, in this order, in the working directory and then each parent up to the
 * repository root or home directory.
 */
export const configFileNames = [
  'better-iam.config.mjs',
  'better-iam.config.js',
  'better-iam.config.ts',
  'better-iam.config.mts',
  'better-iam.config.cjs',
] as const;

/** What a configuration factory receives, so one module can adapt to the command and environment it runs in. */
export interface ConfigContext {
  /** The CLI command being run (`migrate`, `api`, a custom command), or `undefined` outside the CLI. */
  command?: string;
  env: NodeJS.ProcessEnv;
  cwd: string;
}

/** A configuration module's default export: options, a ready instance, or a (possibly async) factory of either. */
export type ConfigExport =
  | BetterIamOptions
  | BetterIam
  | ((
      context: ConfigContext,
    ) => BetterIamOptions | BetterIam | Promise<BetterIamOptions | BetterIam>);

/**
 * Settings the CLI reads from the configuration module's named `cli` export: defaults for the flags of commands that
 * load the configuration or act as a token (`'*'` applies to every such command that has the flag), used when neither
 * the flag nor its environment variable is set.
 */
export interface CliSettings {
  defaults?: Record<string, Record<string, string | number | boolean>>;
}

/**
 * The shape of `better-iam.config.{mjs,ts}`: the default export configures the deployment, `commands` adds project
 * commands to the CLI (`defineCommand`), and `cli` sets flag defaults.
 */
export interface ConfigModule {
  default?: ConfigExport;
  commands?: readonly CommandSpec<any>[];
  cli?: CliSettings;
}

export interface ResolvedConfigPath {
  path: string;
  /** `profile`: the configuration a saved session was issued through. */
  source: 'flag' | 'env' | 'discovered' | 'profile';
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether a found configuration may be imported without being named: on POSIX systems, a file another user owns, or
 * one in a directory anyone may write to (such as /tmp), could have been planted there, and importing it runs it.
 */
async function trustworthy(candidate: string): Promise<boolean> {
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (uid === undefined) return true;
  try {
    const [file, directory] = await Promise.all([stat(candidate), stat(dirname(candidate))]);
    return (file.uid === uid || file.uid === 0) && (directory.mode & 0o002) === 0;
  } catch {
    return false;
  }
}

/**
 * The nearest configuration file in `cwd` or one of its parents, like Prettier and ESLint find theirs, without leaving
 * the repository: the search stops at the repository root (a directory holding `.git`) or the home directory, and skips
 * files another user could have planted (see `trustworthy`).
 */
export async function findConfigFile(cwd: string): Promise<string | undefined> {
  let directory = resolve(cwd);
  const home = resolve(homedir());
  for (;;) {
    for (const name of configFileNames) {
      const candidate = join(directory, name);
      if ((await exists(candidate)) && (await trustworthy(candidate))) return candidate;
    }
    if (directory === home || (await exists(join(directory, '.git')))) return undefined;
    const parent = dirname(directory);
    if (parent === directory) return undefined;
    directory = parent;
  }
}

/** `--config`, else `BETTER_IAM_CONFIG`, else the nearest configuration file; undefined when there is none. */
export async function resolveConfigPath(
  flag: string | undefined,
  env: NodeJS.ProcessEnv,
  cwd: string,
): Promise<ResolvedConfigPath | undefined> {
  if (flag) return { path: resolve(cwd, flag), source: 'flag' };
  if (env.BETTER_IAM_CONFIG) return { path: resolve(cwd, env.BETTER_IAM_CONFIG), source: 'env' };
  const found = await findConfigFile(cwd);
  return found ? { path: found, source: 'discovered' } : undefined;
}

/** Imports a trusted configuration module (it is executable code), with readable errors for the usual mistakes. */
export async function importConfigModule(path: string): Promise<ConfigModule> {
  if (!(await exists(path)))
    throw new CliError(
      'CONFIG_NOT_FOUND',
      `Configuration ${path} does not exist`,
      'Run better-iam init to create one, pass --config PATH, or set BETTER_IAM_CONFIG.',
    );
  try {
    return (await import(pathToFileURL(path).href)) as ConfigModule;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ERR_UNKNOWN_FILE_EXTENSION' && /\.[cm]?ts$/.test(path))
      throw new CliError(
        'CONFIG_LOAD_FAILED',
        `Node.js ${process.versions.node} cannot load the TypeScript configuration ${path}`,
        'Use Node.js 22.18 or later (type stripping is on by default there), or rename it to .mjs.',
      );
    throw error;
  }
}

function isInstance(value: unknown): value is BetterIam {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'api' in value &&
      'initialize' in value &&
      typeof (value as BetterIam).initialize === 'function',
  );
}

/** Creates the IAM instance a module's default export describes (calling a factory with `context`). */
export async function instantiate(
  module: ConfigModule,
  context: ConfigContext,
): Promise<BetterIam> {
  const exported = module.default;
  const configuration = typeof exported === 'function' ? await exported(context) : exported;
  if (!configuration)
    throw new IamError(
      'INVALID_CONFIG',
      'Configuration must export a default options object or factory',
    );
  return isInstance(configuration) ? configuration : betterIam(configuration as BetterIamOptions);
}

/**
 * Loads a configuration file and creates its instance: the same resolution the CLI uses, for scripts, workers, and
 * tests that want `better-iam.config.mjs` without the command line. Close `instance.store` when done.
 */
export async function loadConfig(
  options: { config?: string; cwd?: string; env?: NodeJS.ProcessEnv; command?: string } = {},
): Promise<BetterIam> {
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const located = await resolveConfigPath(options.config, env, cwd);
  if (!located) {
    if (env.BETTER_IAM_DATABASE_URL) return betterIam(await configFromEnv(env));
    throw new CliError(
      'CONFIG_NOT_FOUND',
      `No ${configFileNames[0]} (or .js/.ts) in ${cwd} or its parents`,
      'Run better-iam init, pass --config PATH, set BETTER_IAM_CONFIG, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET.',
    );
  }
  return instantiate(await importConfigModule(located.path), {
    env,
    cwd,
    ...(options.command ? { command: options.command } : {}),
  });
}

const list = (value: string | undefined) =>
  value
    ?.split(',')
    .map((item) => item.trim())
    .filter(Boolean);

/**
 * Deployment options from environment variables alone (twelve-factor style), for containers and CI jobs that have
 * no configuration file:
 *
 * - `BETTER_IAM_DATABASE_URL` (required): `postgres://…`, `sqlite:./iam.db` (or a path ending in `.db`), or
 *   `libsql://…` / `file:…` (needs `@better-iam/adapter-libsql` installed; `BETTER_IAM_DATABASE_TOKEN` authenticates)
 * - `BETTER_IAM_SECRET` (required), `BETTER_IAM_PREVIOUS_SECRETS` (comma-separated, during a rotation)
 * - `BETTER_IAM_BASE_URL` (default `http://localhost:3000`), `BETTER_IAM_BASE_PATH`, `BETTER_IAM_TRUSTED_ORIGINS`
 *
 * Everything else keeps its default; spread the result and add callbacks (email, resolvers) in code when you need
 * them: `betterIam({ ...(await configFromEnv()), authentication: { sendEmail } })`.
 */
export async function configFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Promise<BetterIamOptions> {
  const url = env.BETTER_IAM_DATABASE_URL;
  if (!url) throw new IamError('MISSING_ENV', 'Set BETTER_IAM_DATABASE_URL');
  if (!env.BETTER_IAM_SECRET) throw new IamError('MISSING_ENV', 'Set BETTER_IAM_SECRET');
  let database: BetterIamOptions['database'];
  if (/^postgres(?:ql)?:\/\//i.test(url)) database = postgresAdapter({ connectionString: url });
  else if (/^sqlite:/i.test(url))
    database = sqliteAdapter({ filename: url.replace(/^sqlite:(\/\/)?/i, '') || ':memory:' });
  else if (/^(libsql|wss?|https?):\/\//i.test(url) || /^file:/i.test(url)) {
    const specifier = '@better-iam/adapter-libsql';
    let adapter: {
      libsqlAdapter(options: { url: string; authToken?: string }): BetterIamOptions['database'];
    };
    try {
      adapter = await import(specifier);
    } catch {
      throw new CliError(
        'MISSING_DEPENDENCY',
        'A libSQL database URL needs @better-iam/adapter-libsql',
        'Install it next to better-iam (npm install @better-iam/adapter-libsql).',
      );
    }
    database = adapter.libsqlAdapter({
      url,
      ...(env.BETTER_IAM_DATABASE_TOKEN ? { authToken: env.BETTER_IAM_DATABASE_TOKEN } : {}),
    });
  } else if (/\.(db|sqlite3?)$/i.test(url) || url === ':memory:')
    database = sqliteAdapter({ filename: url });
  else
    throw new IamError(
      'INVALID_CONFIG',
      'BETTER_IAM_DATABASE_URL must be postgres://…, sqlite:PATH, file:PATH, or libsql://…',
    );
  const previousSecrets = list(env.BETTER_IAM_PREVIOUS_SECRETS);
  const trustedOrigins = list(env.BETTER_IAM_TRUSTED_ORIGINS);
  return {
    database,
    secret: env.BETTER_IAM_SECRET,
    baseURL: env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
    ...(env.BETTER_IAM_BASE_PATH ? { basePath: env.BETTER_IAM_BASE_PATH } : {}),
    ...(previousSecrets?.length ? { previousSecrets } : {}),
    ...(trustedOrigins?.length ? { trustedOrigins } : {}),
  };
}
