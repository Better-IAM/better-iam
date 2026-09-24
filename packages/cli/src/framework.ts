import { access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { betterIam, type BetterIam } from '@better-iam/server';
import {
  importConfigModule,
  instantiate,
  resolveConfigPath,
  configFromEnv,
  configFileNames,
  type ConfigModule,
  type ResolvedConfigPath,
} from './config.js';
import { CliError, didYouMean, usageError } from './errors.js';
import { formatResult, outputFormats, type OutputFormat } from './output.js';
import { createProfileStore, type ProfileStore, type StoredProfile } from './profiles.js';
import { localTransport, remoteTransport, sameEndpoint, type ApiTransport } from './transport.js';

/** Where the CLI writes, reads, and prompts. Everything is injectable so programs and tests can run commands. */
export interface CliIO {
  /** Command results (stdout). */
  out(message: string): void;
  /** The environment the command reads (tokens, defaults, credentials file); never `process.env` implicitly. */
  env: NodeJS.ProcessEnv;
  /** Progress and warnings (stderr). Silent when absent. */
  err?(message: string): void;
  /** Asks the person a question; `hidden` for passwords. Absent in non-interactive runs, which then fail instead. */
  prompt?(question: string, options?: { hidden?: boolean }): Promise<string>;
  /** Reads all of standard input (`--data -`, `login --with-token`). */
  stdin?(): Promise<string>;
  /** The directory relative paths and configuration discovery start from (default `process.cwd()`). */
  cwd?: string;
  /** The Fetch implementation remote (`--url`) calls use (default `globalThis.fetch`). */
  fetch?: typeof globalThis.fetch;
}

/** One flag of a command. Keys of a command's `flags` object are the flag names without the leading `--`. */
export interface FlagSpec {
  type: 'string' | 'integer' | 'boolean';
  /** What one line of help says the flag does. */
  description: string;
  /** Placeholder in usage lines (`PATH`, `TENANT_ID`, `N`); defaults by type. */
  value?: string;
  required?: boolean;
  /** An environment variable read when the flag is not given, for example `BETTER_IAM_TENANT`. */
  env?: string;
  /** Allowed values of a string flag. */
  choices?: readonly string[];
  /** Bounds of an integer flag. */
  min?: number;
  max?: number;
  /** The default the command applies, shown in help (the command applies it itself). */
  default?: string | number | boolean;
  /** Token commands: the saved profile field used when neither the flag nor its variable is set. */
  profile?: 'tenantId';
  /** Left out of help and completion (still accepted). */
  hidden?: boolean;
  /**
   * `false`: a `cli.defaults['*']` entry never fills this flag, only one for this very command. For flags whose meaning
   * differs between commands where a shared default could destroy data (how much audit history `audit-prune` keeps).
   */
  wildcardDefault?: boolean;
}
export type FlagSpecs = Record<string, FlagSpec>;

export interface ArgSpec {
  name: string;
  description: string;
  required?: boolean;
  /** Collects every remaining positional argument. Only the last argument may be variadic. */
  variadic?: boolean;
}

type FlagValue<S extends FlagSpec> = S['type'] extends 'boolean'
  ? boolean
  : S['type'] extends 'integer'
    ? number | undefined
    : string | undefined;
/** The parsed flags a command receives: booleans, numbers (or undefined), and strings (or undefined). */
export type FlagValues<F extends FlagSpecs> = { [K in keyof F]: FlagValue<F[K]> };

/** Flags the CLI adds by command kind: `config` for configuration commands, plus `url`/`profile` for token commands, plus output flags. */
export interface CommonFlags {
  config?: string;
  url?: string;
  profile?: string;
  format?: OutputFormat;
  query?: string;
}

/**
 * - `config`: a deployment operation; loads the configuration (`--config`, `BETTER_IAM_CONFIG`, or the nearest
 *   `better-iam.config.*`) and runs with no credential.
 * - `token`: acts as a session or API key (`BETTER_IAM_TOKEN` or the profile saved by `login`), in process through
 *   the configuration or remotely with `--url`; authorized and audited like any client.
 * - `none`: needs neither.
 */
export type CommandTarget = 'config' | 'token' | 'none';

export interface CommandContext<F extends FlagSpecs = FlagSpecs> {
  /** The command name as registered. */
  readonly name: string;
  readonly flags: FlagValues<F> & CommonFlags;
  /** Positional arguments. */
  readonly args: string[];
  /** The flags given on the command line itself (not filled from the environment, defaults, or a profile). */
  readonly explicit: ReadonlySet<string>;
  readonly io: CliIO;
  readonly env: NodeJS.ProcessEnv;
  readonly cwd: string;
  /** Resolves a path against the working directory. */
  path(value: string): string;
  /** Prints a result with `--format` / `--query` applied. Returning a value from `run` does the same. */
  print(value: unknown): void;
  /** Writes a line to stderr (progress, warnings); silent when the IO has no `err`. */
  note(message: string): void;
  /** Where the configuration comes from, or undefined when none was given or found. */
  configPath(): Promise<ResolvedConfigPath | undefined>;
  /** The configuration module (imported once). */
  configModule(): Promise<ConfigModule>;
  /** The IAM instance of the configuration, created once and closed after the command. */
  iam(): Promise<BetterIam>;
  /**
   * Another configuration's instance (for example `store-copy --target-config`), or with no path the deployment the
   * environment describes (`BETTER_IAM_DATABASE_URL`); also closed after the command.
   */
  open(configPath?: string): Promise<BetterIam>;
  /** The bearer token: `BETTER_IAM_TOKEN`, else the saved profile's. */
  token(): Promise<string>;
  /**
   * The saved profile in use, when the command is not acting on `BETTER_IAM_TOKEN`. `profile` is undefined when there
   * is none, or when it belongs to another deployment than `--url` / `--config` name (then `mismatch` holds it).
   */
  profile(): Promise<
    { name: string; profile: StoredProfile | undefined; mismatch?: StoredProfile } | undefined
  >;
  /** Calls API routes as the token (or with no credential when `authenticated` is false). */
  api(options?: { authenticated?: boolean; token?: string }): Promise<ApiTransport>;
  readonly profiles: ProfileStore;
  /** The program running the command: its commands (with the configuration's project commands) and version. */
  readonly program: { readonly commands: readonly CommandSpec<any>[]; readonly version: string };
}

export interface CommandSpec<F extends FlagSpecs = FlagSpecs> {
  name: string;
  /** Section in `help`: Setup, Operations, Audit, Storage, Access, API, Session, Shell, or your own. */
  group?: string;
  /** One line, starting with a verb. */
  summary: string;
  /** Paragraphs of detail for `help <command>` and the reference documentation. */
  description?: string;
  /** Replaces the generated usage line. */
  usage?: string;
  flags?: F;
  args?: ArgSpec[];
  examples?: string[];
  aliases?: string[];
  target?: CommandTarget;
  /** `text` commands print plain text and take no `--format` / `--query`. */
  output?: 'json' | 'text';
  /** The format used when `--format` is not given (default `json`), for commands whose output scripts read by line. */
  defaultFormat?: OutputFormat;
  /** Whether `cli.defaults` from the configuration module apply (imports the module before the command runs). */
  configDefaults?: boolean;
  /**
   * Cross-flag checks after parsing, before the command runs. Throw `usageError(...)`. `explicit` names the flags
   * given on the command line, as opposed to filled from the environment, configuration defaults, or a profile.
   */
  validate?(
    flags: FlagValues<F> & CommonFlags,
    args: string[],
    explicit: ReadonlySet<string>,
  ): void;
  run(context: CommandContext<F>): Promise<unknown> | unknown;
}

/**
 * Declares a CLI command with typed flags. Export an array of them as `commands` from `better-iam.config.mjs` to add
 * project commands (seeding, reports, migrations of your own) that get the same flag parsing, help, configuration
 * loading, and output formatting as the built-in ones.
 *
 * ```js
 * export const commands = [
 *   defineCommand({
 *     name: 'seed',
 *     summary: 'Create the demo organization',
 *     target: 'config',
 *     flags: { slug: { type: 'string', description: 'Organization slug', default: 'demo' } },
 *     async run({ iam, flags }) { const instance = await iam(); ... return { created: true }; },
 *   }),
 * ];
 * ```
 */
export function defineCommand<const F extends FlagSpecs = Record<never, FlagSpec>>(
  spec: CommandSpec<F>,
): CommandSpec<F> {
  return spec;
}

/** Flags that choose the deployment and session; configuration defaults never set them. */
const targetFlags = new Set(['config', 'url', 'profile']);

const configFlag: FlagSpec = {
  type: 'string',
  value: 'PATH',
  env: 'BETTER_IAM_CONFIG',
  description: `Configuration module; default: the nearest ${configFileNames[0]}, .js, or .ts`,
};
const urlFlag: FlagSpec = {
  type: 'string',
  value: 'URL',
  env: 'BETTER_IAM_URL',
  description:
    'Call a running IAM server (https://host or https://host/api/iam) instead of loading the configuration',
};
const profileFlag: FlagSpec = {
  type: 'string',
  value: 'NAME',
  env: 'BETTER_IAM_PROFILE',
  description: 'Saved session to act as (see login); ignored while BETTER_IAM_TOKEN is set',
};
const formatFlag: FlagSpec = {
  type: 'string',
  value: 'FORMAT',
  choices: outputFormats,
  description: 'Output as json (indented, default), compact (one line), or table',
};
const queryFlag: FlagSpec = {
  type: 'string',
  value: 'PATH',
  description:
    'Print only part of the result, e.g. summary.create or findings[].kind (strings print raw)',
};

/** Every flag a command accepts: its own, then the ones its target and output add. */
export function commandFlags(spec: CommandSpec<any>): FlagSpecs {
  const flags: FlagSpecs = { ...(spec.flags ?? {}) };
  const target = spec.target ?? 'none';
  if ((target === 'config' || target === 'token') && !flags.config) flags.config = configFlag;
  if (target === 'token') {
    flags.url ??= urlFlag;
    flags.profile ??= profileFlag;
  }
  if ((spec.output ?? 'json') === 'json') {
    flags.format ??= formatFlag;
    flags.query ??= queryFlag;
  }
  return flags;
}

const placeholder = (flag: FlagSpec) =>
  flag.value ?? (flag.choices ? flag.choices.join('|') : flag.type === 'integer' ? 'N' : 'VALUE');

/** The usage line: required flags as `--flag VALUE`, optional ones in brackets; common flags are left to help. */
export function usageLine(spec: CommandSpec<any>): string {
  if (spec.usage) return spec.usage;
  const parts = [`better-iam ${spec.name}`];
  const target = spec.target ?? 'none';
  if (target === 'config' || target === 'token' || spec.flags?.config)
    parts.push('--config better-iam.config.mjs');
  for (const arg of spec.args ?? []) {
    const name = `${arg.name.toUpperCase()}${arg.variadic ? '...' : ''}`;
    parts.push(arg.required ? name : `[${name}]`);
  }
  for (const [name, flag] of Object.entries((spec.flags ?? {}) as FlagSpecs)) {
    if (name === 'config' || flag.hidden) continue;
    const text = flag.type === 'boolean' ? `--${name}` : `--${name} ${placeholder(flag)}`;
    parts.push(flag.required ? text : `[${text}]`);
  }
  if (target === 'token') parts.push('[--url URL]', '[--profile NAME]');
  return parts.join(' ');
}

function wrap(text: string, indent = 2, width = 80): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split(/\n\s*\n/)) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      if (line && indent + line.length + 1 + word.length > width) {
        lines.push(' '.repeat(indent) + line);
        line = word;
      } else line = line ? `${line} ${word}` : word;
    }
    if (line) lines.push(' '.repeat(indent) + line);
    lines.push('');
  }
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

function flagLines(spec: CommandSpec<any>): string[] {
  const entries = Object.entries(commandFlags(spec)).filter(([, flag]) => !flag.hidden);
  const labels = entries.map(([name, flag]) =>
    flag.type === 'boolean' ? `--${name}` : `--${name} ${placeholder(flag)}`,
  );
  const width = Math.min(30, Math.max(...labels.map((label) => label.length), 10));
  const lines = entries.flatMap(([, flag], index) => {
    const notes = [
      flag.required ? 'required' : undefined,
      flag.default !== undefined ? `default ${flag.default}` : undefined,
      flag.env ? `env ${flag.env}` : undefined,
      flag.profile ? 'or the saved profile' : undefined,
    ].filter(Boolean);
    const description = `${flag.description}${notes.length ? ` (${notes.join('; ')})` : ''}`;
    const label = labels[index]!;
    const wrapped = wrap(description, width + 6, 100).map((line) => line.trimStart());
    return label.length > width
      ? [`  ${label}`, ...wrapped.map((line) => `${' '.repeat(width + 6)}${line}`)]
      : [
          `  ${label.padEnd(width)}    ${wrapped[0] ?? ''}`,
          ...wrapped.slice(1).map((line) => `${' '.repeat(width + 6)}${line}`),
        ];
  });
  return [...lines, `  ${'-h, --help'.padEnd(width)}    Show this help`];
}

/** `better-iam help <command>`: usage, description, arguments, flags, and examples. */
export function commandHelp(spec: CommandSpec<any>): string {
  const lines = [`better-iam ${spec.name} - ${spec.summary}`, '', 'Usage', `  ${usageLine(spec)}`];
  if (spec.aliases?.length) lines.push('', `Aliases: ${spec.aliases.join(', ')}`);
  if (spec.description) lines.push('', ...wrap(spec.description));
  if (spec.args?.length) {
    lines.push('', 'Arguments');
    const width = Math.max(...spec.args.map((arg) => arg.name.length + 3));
    for (const arg of spec.args)
      lines.push(`  ${arg.name.toUpperCase().padEnd(width)}  ${arg.description}`);
  }
  lines.push('', 'Flags', ...flagLines(spec));
  if (spec.examples?.length)
    lines.push('', 'Examples', ...spec.examples.map((example) => `  $ ${example}`));
  return lines.join('\n');
}

/** Environment variables the CLI reads, for help and the manifest. */
export const environmentVariables: { name: string; description: string }[] = [
  { name: 'BETTER_IAM_CONFIG', description: 'Configuration module, like --config' },
  { name: 'BETTER_IAM_TOKEN', description: 'Session or API key token commands act as' },
  { name: 'BETTER_IAM_URL', description: 'IAM server token commands call, like --url' },
  { name: 'BETTER_IAM_PROFILE', description: 'Saved session to use, like --profile' },
  { name: 'BETTER_IAM_TENANT', description: 'Default --tenant for token commands' },
  {
    name: 'BETTER_IAM_CREDENTIALS',
    description:
      'File saved sessions live in (default ~/.config/better-iam/credentials.json, %APPDATA% on Windows)',
  },
  {
    name: 'BETTER_IAM_ROOT_EMAIL',
    description:
      'bootstrap / recover-root: the root administrator (with BETTER_IAM_ROOT_NAME, BETTER_IAM_ROOT_PASSWORD)',
  },
  { name: 'BETTER_IAM_ROOT_NAME', description: 'bootstrap / recover-root: display name' },
  {
    name: 'BETTER_IAM_ROOT_PASSWORD',
    description: 'bootstrap / recover-root: password (never a flag)',
  },
  { name: 'BETTER_IAM_PASSWORD', description: 'login: the password, instead of the prompt' },
  {
    name: 'BETTER_IAM_MFA_CODE',
    description: 'login: the authenticator code, instead of the prompt',
  },
  {
    name: 'BETTER_IAM_DATABASE_URL',
    description:
      'Without a configuration file: the database (postgres://, sqlite:PATH, libsql://), with BETTER_IAM_SECRET',
  },
  { name: 'BETTER_IAM_SECRET', description: 'Without a configuration file: the deployment secret' },
];

/** A machine-readable description of every command: what `better-iam help --json` prints and the docs are built from. */
export interface CliManifest {
  name: 'better-iam';
  version: string;
  commands: {
    name: string;
    aliases: string[];
    group: string;
    summary: string;
    description: string;
    usage: string;
    target: CommandTarget;
    args: ArgSpec[];
    flags: {
      flag: string;
      value?: string;
      optional: boolean;
      description: string;
      env?: string;
      default?: string | number | boolean;
      choices?: readonly string[];
    }[];
    examples: string[];
  }[];
  env: { name: string; description: string }[];
}

export function manifestOf(commands: readonly CommandSpec<any>[], version: string): CliManifest {
  return {
    name: 'better-iam',
    version,
    commands: commands.map((spec) => ({
      name: spec.name,
      aliases: spec.aliases ?? [],
      group: spec.group ?? 'Commands',
      summary: spec.summary,
      description: spec.description ?? spec.summary,
      usage: usageLine(spec),
      target: spec.target ?? 'none',
      args: spec.args ?? [],
      flags: Object.entries(commandFlags(spec))
        .filter(([, flag]) => !flag.hidden)
        .map(([name, flag]) => ({
          flag: `--${name}`,
          ...(flag.type === 'boolean' ? {} : { value: placeholder(flag) }),
          optional: !flag.required,
          description: flag.description,
          ...(flag.env ? { env: flag.env } : {}),
          ...(flag.default !== undefined ? { default: flag.default } : {}),
          ...(flag.choices ? { choices: flag.choices } : {}),
        })),
      examples: spec.examples ?? [],
    })),
    env: environmentVariables,
  };
}

const groupOrder = ['Setup', 'Operations', 'Audit', 'Storage', 'Access', 'API', 'Session', 'Shell'];

/** `better-iam help`: every command by section, every usage line, the details, and the environment. */
export function overviewHelp(commands: readonly CommandSpec<any>[], version: string): string {
  const groups = new Map<string, CommandSpec<any>[]>();
  for (const spec of commands) {
    const group = spec.group ?? 'Commands';
    groups.set(group, [...(groups.get(group) ?? []), spec]);
  }
  const ordered = [...groups.keys()].sort(
    (a, b) =>
      (groupOrder.indexOf(a) + 1 || 99) - (groupOrder.indexOf(b) + 1 || 99) || a.localeCompare(b),
  );
  const width = Math.max(...commands.map((spec) => spec.name.length)) + 2;
  const lines = [
    `Better IAM ${version}`,
    '',
    'Usage',
    '  better-iam <command> [flags]',
    '  better-iam help <command>      flags, details, and examples for one command',
    '  better-iam help --json         every command as JSON, for tools',
    '',
  ];
  for (const group of ordered) {
    lines.push(group);
    for (const spec of groups.get(group)!)
      lines.push(`  ${spec.name.padEnd(width)}${spec.summary}`);
    lines.push('');
  }
  lines.push('Commands', ...commands.map((spec) => `  ${usageLine(spec)}`), '');
  lines.push(
    ...wrap(
      'Configuration commands load better-iam.config.mjs (or --config, BETTER_IAM_CONFIG, the nearest better-iam.config.* in a parent directory, or BETTER_IAM_DATABASE_URL + BETTER_IAM_SECRET without a file). Token commands act as BETTER_IAM_TOKEN or the session saved by login, in process or against --url, and are authorized and audited like console operations. Secrets are never accepted in command-line arguments. Every flag also accepts --flag=value; results print as JSON unless --format says otherwise.',
    ),
    '',
  );
  for (const spec of commands) if (spec.description) lines.push(...wrap(spec.description), '');
  lines.push('Environment');
  const envWidth = Math.max(...environmentVariables.map((entry) => entry.name.length)) + 2;
  for (const entry of environmentVariables)
    lines.push(`  ${entry.name.padEnd(envWidth)}${entry.description}`);
  return lines.join('\n');
}

interface Parsed {
  values: Map<string, string | boolean>;
  args: string[];
  help: boolean;
}

/** Parses `--flag value`, `--flag=value`, boolean `--flag`, `--` and positionals for one command. */
export function parseArguments(spec: CommandSpec<any>, argv: string[]): Parsed {
  const flags = commandFlags(spec);
  const values = new Map<string, string | boolean>();
  const args: string[] = [];
  let help = false;
  let positionalOnly = false;
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index]!;
    if (positionalOnly) {
      args.push(token);
      continue;
    }
    if (token === '--') {
      positionalOnly = true;
      continue;
    }
    if (token === '--help' || token === '-h') {
      help = true;
      continue;
    }
    if (token.startsWith('--')) {
      const equals = token.indexOf('=');
      const name = equals === -1 ? token.slice(2) : token.slice(2, equals);
      const inline = equals === -1 ? undefined : token.slice(equals + 1);
      const flag = Object.hasOwn(flags, name) ? flags[name] : undefined;
      if (!flag)
        throw usageError(
          `${spec.name} does not take --${name}.${didYouMean(name, Object.keys(flags), '--')}`,
          `Run better-iam help ${spec.name} for its flags.`,
        );
      if (values.has(name)) throw usageError(`--${name} was given more than once`);
      if (flag.type === 'boolean') {
        if (inline === undefined) values.set(name, true);
        else if (inline === 'true' || inline === 'false') values.set(name, inline === 'true');
        else throw usageError(`--${name} is a switch; use --${name} or --${name}=false`);
        continue;
      }
      const value = inline ?? argv[++index];
      if (value === undefined || value === '' || (inline === undefined && value.startsWith('--')))
        throw usageError(`--${name} needs a value (${placeholder(flag)})`);
      values.set(name, value);
      continue;
    }
    if (token.startsWith('-') && token !== '-' && !spec.args?.length)
      throw usageError(`${spec.name} does not take ${token}`, `Run better-iam help ${spec.name}.`);
    args.push(token);
  }
  const specs = spec.args ?? [];
  if (!specs.length && args.length)
    throw usageError(
      `${spec.name} takes no arguments (got ${args[0]})`,
      `Flags start with --; run better-iam help ${spec.name}.`,
    );
  if (!specs.at(-1)?.variadic && args.length > specs.length)
    throw usageError(`${spec.name} takes at most ${specs.length} argument(s)`);
  return { values, args, help };
}

/** Checks and converts one raw flag value (from argv, the environment, or configuration defaults). */
function convert(
  name: string,
  flag: FlagSpec,
  raw: string | boolean | number,
  source: string,
): string | number | boolean {
  const label = source === 'flag' ? `--${name}` : `${source} (for --${name})`;
  if (flag.type === 'boolean') {
    if (typeof raw === 'boolean') return raw;
    if (['true', '1', 'yes'].includes(String(raw).toLowerCase())) return true;
    if (['false', '0', 'no', ''].includes(String(raw).toLowerCase())) return false;
    throw usageError(`${label} must be true or false`);
  }
  if (flag.type === 'integer') {
    const text = String(raw);
    const number = Number(text);
    const min = flag.min ?? Number.MIN_SAFE_INTEGER;
    const max = flag.max ?? Number.MAX_SAFE_INTEGER;
    if (!/^-?\d+$/.test(text) || !Number.isSafeInteger(number) || number < min || number > max)
      throw usageError(
        flag.min !== undefined || flag.max !== undefined
          ? `${label} must be an integer between ${min} and ${max}`
          : `${label} must be an integer`,
      );
    return number;
  }
  const text = String(raw);
  if (!text) throw usageError(`${label} needs a value`);
  if (flag.choices && !flag.choices.includes(text))
    throw usageError(`${label} must be ${flag.choices.join(', ')}`);
  return text;
}

export interface CreateCliOptions {
  /** Commands in addition to (or, with `builtins: false`, instead of) the built-in ones. */
  commands?: readonly CommandSpec<any>[];
  /** Keep the built-in commands (default true). */
  builtins?: boolean;
  version?: string;
}

/** A command-line program: the built-in commands plus yours, runnable from code with any IO. */
export interface Cli {
  readonly commands: readonly CommandSpec<any>[];
  run(argv: string[], io?: CliIO): Promise<void>;
  help(command?: string): string;
  manifest(): CliManifest;
}

/**
 * Commands a configuration module exports (`export const commands = [...]`). A configuration is executable code, so
 * with `discover: false` (help and shell completion, which shells run on their own at startup, possibly in a directory
 * someone else controls) only a configuration named with `--config` or `BETTER_IAM_CONFIG` is imported.
 */
async function configCommands(
  argv: string[],
  io: CliIO,
  cwd: string,
  discover = true,
): Promise<CommandSpec<any>[]> {
  let flag: string | undefined;
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index]!;
    if (token === '--config') flag = argv[index + 1];
    else if (token.startsWith('--config=')) flag = token.slice('--config='.length);
  }
  if (!discover && !flag && !io.env.BETTER_IAM_CONFIG) return [];
  const located = await resolveConfigPath(flag, io.env, cwd);
  if (!located) return [];
  const module = await importConfigModule(located.path);
  return Array.isArray(module.commands) ? [...module.commands] : [];
}

export function createCliProgram(
  builtins: readonly CommandSpec<any>[],
  version: string,
  defaultIO: () => CliIO,
): (options?: CreateCliOptions) => Cli {
  return (options = {}) => {
    const commands = [...(options.builtins === false ? [] : builtins), ...(options.commands ?? [])];
    const cliVersion = options.version ?? version;
    const find = (list: readonly CommandSpec<any>[], name: string) =>
      list.find((spec) => spec.name === name || spec.aliases?.includes(name));
    const cli: Cli = {
      commands,
      help: (name) => {
        if (!name) return overviewHelp(commands, cliVersion);
        const spec = find(commands, name);
        if (!spec)
          throw new CliError(
            'INVALID_COMMAND',
            `Unknown command: ${name}.${didYouMean(
              name,
              commands.map((command) => command.name),
            )}`,
          );
        return commandHelp(spec);
      },
      manifest: () => manifestOf(commands, cliVersion),
      async run(argv, io = defaultIO()) {
        const cwd = io.cwd ?? process.cwd();
        const name = argv[0] ?? 'help';
        if (['help', '--help', '-h'].includes(name)) {
          const rest = argv.slice(1);
          const json = rest.includes('--json');
          const topic = rest.find(
            (item, index) => !item.startsWith('-') && rest[index - 1] !== '--config',
          );
          let all = commands;
          // Project commands appear in help for a configuration named with --config or BETTER_IAM_CONFIG; help never
          // runs a configuration it merely found in the directory.
          try {
            all = [
              ...commands,
              ...(await configCommands(rest, io, cwd, false)).filter(
                (spec) => !find(commands, spec.name),
              ),
            ];
          } catch {
            /* Help never fails because a configuration does not load. */
          }
          if (json)
            io.out(
              JSON.stringify(
                manifestOf(topic ? all.filter((spec) => spec.name === topic) : all, cliVersion),
                null,
                2,
              ),
            );
          else if (topic) {
            const spec = find(all, topic);
            if (!spec)
              throw new CliError(
                'INVALID_COMMAND',
                `Unknown command: ${topic}.${didYouMean(
                  topic,
                  all.map((command) => command.name),
                )}`,
              );
            io.out(commandHelp(spec));
          } else io.out(overviewHelp(all, cliVersion));
          return;
        }
        if (['--version', 'version', '-v'].includes(name)) {
          io.out(cliVersion);
          return;
        }
        let spec = find(commands, name);
        let extra: CommandSpec<any>[] | undefined;
        // An unknown name may be a project command: a configuration that fails to load reports its own error
        // then, instead of "unknown command"; completion scripts skip a broken configuration.
        const projectCommands = async (strict: boolean, discover = true) =>
          (extra ??= await configCommands(argv.slice(1), io, cwd, discover).catch(
            (error: unknown) => {
              if (strict) throw error;
              return [];
            },
          ));
        let rest = argv.slice(1);
        if (!spec && !name.startsWith('-')) {
          spec = find(await projectCommands(true), name);
          // A project command found through --config accepts that flag even when it loads no configuration.
          if (spec && !commandFlags(spec).config)
            rest = rest.filter(
              (token, index) =>
                token !== '--config' &&
                rest[index - 1] !== '--config' &&
                !token.startsWith('--config='),
            );
        }
        if (!spec)
          throw new CliError(
            'INVALID_COMMAND',
            `Unknown command: ${name}.${didYouMean(
              name,
              [...commands, ...(extra ?? [])].flatMap((command) => [
                command.name,
                ...(command.aliases ?? []),
              ]),
            )}`,
            'Run better-iam help for the list of commands.',
          );
        // Completion scripts cover the project commands of a configuration named with --config or BETTER_IAM_CONFIG
        // (shells run completion at startup, so it never imports one it found); other commands never import the
        // module just for this.
        const all =
          spec.name === 'completion'
            ? [
                ...commands,
                ...(await projectCommands(false, false)).filter(
                  (item) => !find(commands, item.name),
                ),
              ]
            : [...commands, ...(extra ?? []).filter((item) => !find(commands, item.name))];
        await execute(spec, rest, io, cwd, { commands: all, version: cliVersion });
      },
    };
    return cli;
  };
}

/** Where a saved profile's session was issued: its server, its configuration, or the environment-only deployment. */
export function describeProfileTarget(profile: StoredProfile): string {
  return (
    profile.url ??
    profile.config ??
    (profile.envConfig ? 'BETTER_IAM_DATABASE_URL' : 'an unknown deployment')
  );
}

async function execute(
  spec: CommandSpec<any>,
  argv: string[],
  io: CliIO,
  cwd: string,
  program: CommandContext['program'],
): Promise<void> {
  const parsed = parseArguments(spec, argv);
  if (parsed.help) {
    io.out(commandHelp(spec));
    return;
  }
  const flags = commandFlags(spec);
  const target = spec.target ?? 'none';
  // Null prototype: a project flag named `constructor` or `toString` must not look already set.
  const values: Record<string, unknown> = Object.create(null);
  const has = (name: string) => Object.hasOwn(values, name);
  const explicit = new Set(parsed.values.keys());
  for (const [name, raw] of parsed.values) values[name] = convert(name, flags[name]!, raw, 'flag');
  for (const [name, flag] of Object.entries(flags))
    if (!has(name) && flag.env && io.env[flag.env])
      values[name] = convert(name, flag, io.env[flag.env]!, flag.env);
  // One deployment per command: the command line beats the environment, and naming both at one level is ambiguous.
  if (target === 'token') {
    if (explicit.has('url') && explicit.has('config'))
      throw usageError('Give --url or --config, not both');
    if (explicit.has('config')) delete values.url;
    else if (explicit.has('url')) delete values.config;
    else if (has('url') && has('config'))
      throw usageError(
        'BETTER_IAM_URL and BETTER_IAM_CONFIG are both set',
        'Pass --url or --config to choose one.',
      );
  }
  const profiles = createProfileStore(io.env);
  // A token in the environment wins over saved profiles entirely: its target and tenant come from flags. A saved
  // session is only ever used with the deployment it was issued by, so its token never reaches another server.
  const usesProfile = target === 'token' && !io.env.BETTER_IAM_TOKEN;
  let profileCache:
    | { name: string; profile: StoredProfile | undefined; mismatch?: StoredProfile }
    | undefined
    | null = null;
  const profile = async () => {
    if (profileCache !== null) return profileCache;
    if (!usesProfile || !profiles.path) return (profileCache = undefined);
    const name = await profiles.currentName(values.profile as string | undefined);
    const saved = await profiles.get(name);
    const matches =
      !saved ||
      (has('url')
        ? saved.url !== undefined && sameEndpoint(saved.url, values.url as string)
        : has('config')
          ? saved.config !== undefined && resolve(cwd, values.config as string) === saved.config
          : true);
    return (profileCache = matches
      ? { name, profile: saved }
      : { name, profile: undefined, mismatch: saved });
  };
  const remoteURL = async (): Promise<string | undefined> => {
    if (has('url')) return values.url as string;
    if (has('config')) return undefined;
    return (await profile())?.profile?.url;
  };
  let located: ResolvedConfigPath | undefined | null = null;
  const configPath = async () => {
    if (located !== null) return located;
    if (!has('config') && target === 'token') {
      // Without --config, a token command uses the deployment its saved session came from.
      const saved = (await profile())?.profile;
      if (saved?.config) return (located = { path: saved.config, source: 'profile' });
      if (saved?.envConfig) return (located = undefined);
    }
    return (located = await resolveConfigPath(values.config as string | undefined, io.env, cwd));
  };
  let moduleCache: Promise<ConfigModule> | undefined;
  const configModule = () => {
    moduleCache ??= (async () => {
      const where = await configPath();
      if (!where) return {};
      return importConfigModule(where.path);
    })();
    return moduleCache;
  };
  // Configuration defaults (`export const cli = { defaults }`) fill flags nobody set; they need the module imported.
  // The flags that choose the deployment and session cannot come from that deployment's own configuration.
  if (
    target !== 'none' &&
    spec.configDefaults !== false &&
    !(target === 'token' && (await remoteURL()))
  ) {
    const where = await configPath();
    const missing = Object.keys(flags).filter((name) => !has(name));
    // A missing file is reported by the command when it loads the configuration, after flag checks.
    const present = where
      ? await access(where.path).then(
          () => true,
          () => false,
        )
      : false;
    if (where && present && missing.length) {
      const defaults = (await configModule()).cli?.defaults ?? {};
      for (const scope of [spec.name, '*'])
        for (const [name, raw] of Object.entries(defaults[scope] ?? {}))
          if (
            Object.hasOwn(flags, name) &&
            !has(name) &&
            !targetFlags.has(name) &&
            !(scope === '*' && flags[name]!.wildcardDefault === false)
          )
            values[name] = convert(name, flags[name]!, raw, `cli.defaults['${scope}']`);
    }
  }
  // Last before the built-in default: the saved session's own values (its tenant).
  for (const [name, flag] of Object.entries(flags))
    if (!has(name) && flag.profile) {
      const saved = (await profile())?.profile?.[flag.profile];
      if (saved) values[name] = saved;
    }
  for (const [name, flag] of Object.entries(flags))
    if (flag.required && values[name] === undefined)
      throw usageError(
        `--${name} ${placeholder(flag)} is required`,
        flag.profile
          ? `Pass --${name}, set ${flag.env ?? 'it'}, or log in with better-iam login --tenant ID.`
          : undefined,
      );
  for (const [name, flag] of Object.entries(flags))
    if (flag.type === 'boolean' && values[name] === undefined) values[name] = false;
  const args = parsed.args;
  for (const [index, arg] of (spec.args ?? []).entries())
    if (arg.required && args[index] === undefined)
      throw usageError(
        `${spec.name} needs ${arg.name.toUpperCase()}`,
        `Run better-iam help ${spec.name}.`,
      );
  spec.validate?.(values as never, args, explicit);

  const opened: BetterIam[] = [];
  let instance: Promise<BetterIam> | undefined;
  const iam = () => {
    instance ??= (async () => {
      const where = await configPath();
      let created: BetterIam;
      if (where)
        created = await instantiate(await configModule(), { command: spec.name, env: io.env, cwd });
      else if (io.env.BETTER_IAM_DATABASE_URL) created = betterIam(await configFromEnv(io.env));
      else
        throw new CliError(
          'CONFIG_NOT_FOUND',
          `No ${configFileNames[0]} (or .js/.ts) in ${cwd} or its parents`,
          target === 'token'
            ? 'Pass --config PATH or --url URL, run better-iam login, or run better-iam init.'
            : 'Run better-iam init, pass --config PATH, or set BETTER_IAM_DATABASE_URL and BETTER_IAM_SECRET.',
        );
      opened.push(created);
      return created;
    })();
    return instance;
  };
  const token = async () => {
    const fromEnv = io.env.BETTER_IAM_TOKEN;
    if (fromEnv) return fromEnv;
    const saved = await profile();
    if (saved?.profile?.token) {
      if (saved.profile.expiresAt !== undefined && saved.profile.expiresAt <= Date.now())
        throw new CliError(
          'SESSION_EXPIRED',
          `The session saved as profile ${saved.name} has expired`,
          `Run better-iam login${saved.name === 'default' ? '' : ` --profile ${saved.name}`} again.`,
        );
      return saved.profile.token;
    }
    if (saved?.mismatch)
      throw new CliError(
        'MISSING_ENV',
        'Set BETTER_IAM_TOKEN to a session or API key',
        `The saved session "${saved.name}" belongs to ${describeProfileTarget(saved.mismatch)}, not this deployment; run better-iam login against it with another --profile.`,
      );
    throw new CliError(
      'MISSING_ENV',
      'Set BETTER_IAM_TOKEN to a session or API key',
      'Or sign in once with better-iam login; later commands use the saved session.',
    );
  };
  const context: CommandContext<FlagSpecs> = {
    name: spec.name,
    flags: values as never,
    args,
    explicit,
    io,
    env: io.env,
    cwd,
    profiles,
    program,
    path: (value) => resolve(cwd, value),
    print: (value) =>
      io.out(
        formatResult(
          value,
          (values.format as OutputFormat | undefined) ?? spec.defaultFormat,
          values.query as string | undefined,
        ),
      ),
    note: (message) => io.err?.(message),
    configPath,
    configModule,
    iam,
    async open(path) {
      const created =
        path === undefined
          ? betterIam(await configFromEnv(io.env))
          : await instantiate(await importConfigModule(resolve(cwd, path)), {
              command: spec.name,
              env: io.env,
              cwd,
            });
      opened.push(created);
      return created;
    },
    token,
    profile,
    async api(options = {}) {
      const bearer = options.token ?? (options.authenticated === false ? undefined : await token());
      const url = await remoteURL();
      if (url) return remoteTransport(url, bearer, io.fetch);
      const where = await configPath();
      return localTransport(await iam(), where?.path ?? 'BETTER_IAM_DATABASE_URL', bearer);
    },
  };
  try {
    const result = await spec.run(context);
    if (result !== undefined) context.print(result);
  } finally {
    for (const created of opened.reverse()) await created.store.close();
  }
}
