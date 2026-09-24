import { spawn } from 'node:child_process';
import { CliError, usageError } from '../errors.js';
import { defineCommand } from '../framework.js';
import { tenantFlag } from './access.js';

interface Revealed {
  name: string;
  version: number;
  format: 'text' | 'json';
  value: string;
  fields?: Record<string, unknown>;
}
interface Listed {
  secrets: { name: string; kind: string; format: string; status: string }[];
  total: number;
}

const envVariable = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * The environment variable a secret under `prefix` becomes in `vault-run --prefix`: the rest of its name upper-cased,
 * with every run of other characters turned into `_` (`prod/app/db-password` under `prod/app/` is `DB_PASSWORD`).
 */
export function secretEnvName(name: string, prefix: string): string {
  const rest = name.startsWith(prefix) ? name.slice(prefix.length) : name;
  const variable = rest
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
  return /^[0-9]/.test(variable) ? `_${variable}` : variable;
}

/** One `VAR=name` or `VAR=name#field` mapping of `vault-run --env`. */
function mapping(entry: string): { variable: string; name: string; field?: string } {
  const equals = entry.indexOf('=');
  if (equals < 1) throw usageError(`--env entries look like VAR=secret/name, not ${entry}`);
  const variable = entry.slice(0, equals).trim();
  const reference = entry.slice(equals + 1).trim();
  if (!envVariable.test(variable)) throw usageError(`${variable} is not an environment variable name`);
  const hash = reference.indexOf('#');
  const name = hash === -1 ? reference : reference.slice(0, hash);
  if (!name) throw usageError(`--env ${variable} names no secret`);
  return hash === -1 ? { variable, name } : { variable, name, field: reference.slice(hash + 1) };
}

/** A revealed value as an environment string: the value, or one field of a json secret (non-strings as JSON). */
function envValue(secret: Revealed, field: string | undefined): string {
  if (field === undefined) return secret.value;
  const value = secret.fields && Object.hasOwn(secret.fields, field) ? secret.fields[field] : undefined;
  if (value === undefined)
    throw new CliError('NOT_FOUND', `The secret ${secret.name} has no field ${field}`);
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/** Runs the command with the environment and resolves with its exit status. */
function runChild(command: string, args: string[], env: NodeJS.ProcessEnv, cwd: string) {
  return new Promise<number>((resolvePromise, reject) => {
    const child = spawn(command, args, { env, cwd, stdio: 'inherit', shell: false });
    child.once('error', (error: NodeJS.ErrnoException) =>
      reject(
        error.code === 'ENOENT'
          ? new CliError('COMMAND_NOT_FOUND', `${command} was not found`, 'Check the command after --.')
          : error,
      ),
    );
    child.once('exit', (code, signal) => resolvePromise(code ?? (signal ? 128 : 1)));
  });
}

/** The secrets vault from the command line: values as BETTER_IAM_TOKEN, and the scheduler jobs. */
export const vaultCommands = [
  defineCommand({
    name: 'vault-get',
    group: 'Access',
    summary: 'Print a secret from the vault',
    description:
      'vault-get prints the value of a secret as BETTER_IAM_TOKEN (iam:vault:reveal): the current version, or --version / --stage, and with --field one field of a json secret. The value is printed on its own, so it can be captured with $(...); every reveal is audited as vault:reveal. Secrets handed out only through check-outs refuse with CHECKOUT_REQUIRED.',
    target: 'token',
    output: 'text',
    args: [{ name: 'name', description: 'The secret, such as prod/payments/db-password', required: true }],
    flags: {
      tenant: tenantFlag,
      version: { type: 'integer', min: 1, max: Number.MAX_SAFE_INTEGER, description: 'A version' },
      stage: { type: 'string', value: 'LABEL', description: 'A stage label such as previous' },
      field: { type: 'string', value: 'FIELD', description: 'One field of a json secret' },
    },
    examples: [
      'better-iam vault-get prod/payments/db-password --tenant acme-id',
      'better-iam vault-get prod/smtp --field password',
    ],
    validate(flags) {
      if (flags.version !== undefined && flags.stage !== undefined)
        throw usageError('Pass --version or --stage, not both');
    },
    async run({ flags, args, api }) {
      const secret = await (await api()).call<Revealed>('vault/reveal', {
        tenantId: flags.tenant!,
        name: args[0]!,
        ...(flags.version !== undefined ? { version: flags.version } : {}),
        ...(flags.stage ? { stage: flags.stage } : {}),
      });
      return envValue(secret, flags.field);
    },
  }),
  defineCommand({
    name: 'vault-put',
    group: 'Access',
    summary: 'Store a new version of a secret',
    description:
      'vault-put stores a new version of a secret as BETTER_IAM_TOKEN (iam:vault:write) from standard input (the default, or --value -), from --value-env (the name of an environment variable holding it), or --generate for a random value; secrets are never taken from the command line itself. The version becomes current unless --stage pending. Trailing newlines on standard input are removed.',
    target: 'token',
    args: [{ name: 'name', description: 'The secret', required: true }],
    flags: {
      tenant: tenantFlag,
      'value-env': {
        type: 'string',
        value: 'VARIABLE',
        description: 'Read the value from this environment variable',
      },
      generate: { type: 'boolean', description: 'Generate a random 32-character value' },
      stage: {
        type: 'string',
        choices: ['current', 'pending'],
        default: 'current',
        description: 'Make it current now, or stage it for promotion',
      },
    },
    examples: [
      'printf %s "$PASSWORD" | better-iam vault-put prod/payments/db-password',
      'better-iam vault-put prod/signing-key --value-env SIGNING_KEY --stage pending',
      'better-iam vault-put staging/api-token --generate',
    ],
    validate(flags) {
      if (flags.generate && flags['value-env'])
        throw usageError('Pass --generate or --value-env, not both');
    },
    async run({ flags, args, api, io, env }) {
      let value: string | undefined;
      if (flags['value-env']) {
        value = env[flags['value-env']];
        if (!value) throw usageError(`${flags['value-env']} is not set or empty`);
      } else if (!flags.generate) {
        if (!io.stdin) throw usageError('Pipe the value on standard input, or use --value-env');
        value = (await io.stdin()).replace(/\r?\n$/, '');
        if (!value) throw usageError('Standard input was empty');
      }
      return (await api()).call('vault/put', {
        tenantId: flags.tenant!,
        name: args[0]!,
        ...(value !== undefined ? { value } : { generate: true }),
        stage: flags.stage ?? 'current',
      });
    },
  }),
  defineCommand({
    name: 'vault-run',
    group: 'Access',
    summary: 'Run a command with secrets in its environment',
    description:
      'vault-run reveals secrets as BETTER_IAM_TOKEN (iam:vault:reveal on each) and runs the command after -- with them as environment variables, so they never touch disk or shell history. --env maps variables to secrets (VAR=name, or VAR=name#field for one field of a json secret; comma-separated). --prefix adds every static secret under a path you may reveal, named after the rest of its path (prod/app/db-password under prod/app/ becomes DB_PASSWORD; a json secret adds one variable per field, DB_PASSWORD_USERNAME). --env wins over --prefix. The command inherits the terminal and its exit status becomes vault-run\'s. BETTER_IAM_TOKEN is removed from the command\'s environment unless --keep-token.',
    target: 'token',
    output: 'text',
    args: [{ name: 'command', description: 'The command and its arguments, after --', required: true, variadic: true }],
    flags: {
      tenant: tenantFlag,
      env: {
        type: 'string',
        value: 'VAR=NAME[#FIELD],...',
        description: 'Variables to set from secrets',
      },
      prefix: {
        type: 'string',
        value: 'PATH/',
        description: 'Add every secret under this path, named after the rest of its name',
      },
      'keep-token': {
        type: 'boolean',
        description: 'Pass BETTER_IAM_TOKEN on to the command',
      },
    },
    examples: [
      'better-iam vault-run --env DATABASE_PASSWORD=prod/payments/db-password -- node server.js',
      'better-iam vault-run --prefix prod/payments/ -- npm start',
    ],
    validate(flags) {
      if (!flags.env && !flags.prefix) throw usageError('Pass --env, --prefix, or both');
    },
    async run({ flags, args, api, env, cwd, note }) {
      const transport = await api();
      const tenantId = flags.tenant!;
      const injected: Record<string, string> = {};
      const cache = new Map<string, Promise<Revealed>>();
      const reveal = (name: string) => {
        if (!cache.has(name))
          cache.set(name, transport.call<Revealed>('vault/reveal', { tenantId, name }));
        return cache.get(name)!;
      };
      if (flags.prefix) {
        const listed = await transport.call<Listed>('vault/list', {
          tenantId,
          prefix: flags.prefix,
          limit: 500,
        });
        for (const secret of listed.secrets) {
          if (secret.kind !== 'static' || secret.status !== 'active') continue;
          const revealed = await reveal(secret.name).catch((error: unknown) => {
            note(`Skipped ${secret.name}: ${(error as Error).message}`);
            return undefined;
          });
          if (!revealed) continue;
          const base = secretEnvName(secret.name, flags.prefix);
          if (revealed.format === 'json' && revealed.fields)
            for (const [field, value] of Object.entries(revealed.fields)) {
              const variable = `${base}_${secretEnvName(field, '')}`;
              if (envVariable.test(variable))
                injected[variable] = typeof value === 'string' ? value : JSON.stringify(value);
            }
          else if (envVariable.test(base)) injected[base] = revealed.value;
        }
      }
      for (const entry of (flags.env ?? '').split(',').filter((item) => item.trim())) {
        const { variable, name, field } = mapping(entry);
        injected[variable] = envValue(await reveal(name), field);
      }
      const childEnv: NodeJS.ProcessEnv = { ...env, ...injected };
      if (!flags['keep-token']) delete childEnv.BETTER_IAM_TOKEN;
      note(`Running ${args[0]} with ${Object.keys(injected).length} secret(s) in its environment`);
      const status = await runChild(args[0]!, args.slice(1), childEnv, cwd);
      if (status !== 0)
        throw Object.assign(
          new CliError('COMMAND_FAILED', `${args[0]} exited with status ${status}`),
          { exitStatus: status },
        );
      return undefined;
    },
  }),
  defineCommand({
    name: 'vault-rotate-due',
    group: 'Operations',
    summary: 'Rotate vault secrets whose scheduled rotation is due',
    description:
      'vault-rotate-due rotates every static secret (or those of --tenant) whose rotation.intervalDays has passed and that has a generator or a rotator, acting as deployment-operator; due secrets with neither are recorded once per due date as vault:rotation-due. Failed rotations keep their pending version and retry with growing delays. Run it hourly.',
    target: 'config',
    flags: {
      tenant: { type: 'string', value: 'TENANT_ID', description: 'Only this tenant' },
    },
    async run({ iam, flags }) {
      return (await iam()).vault.rotateDue(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
  defineCommand({
    name: 'vault-expire-leases',
    group: 'Operations',
    summary: 'End expired vault check-outs and leases',
    description:
      'vault-expire-leases ends expired check-outs (rotating secrets that rotate on check-in), revokes expired dynamic leases and those of people who are no longer active at their engine, retries failed revocations, and deletes lease history past vault.accessRetentionDays. Run it every few minutes.',
    target: 'config',
    flags: {},
    async run({ iam }) {
      return (await iam()).vault.expireLeases();
    },
  }),
  defineCommand({
    name: 'vault-purge-deleted',
    group: 'Operations',
    summary: 'Delete vault secrets whose recovery window has ended',
    description:
      'vault-purge-deleted removes every secret scheduled for deletion whose recovery window has ended, with its versions, leases and access records (live dynamic leases are revoked at their engine first); each is audited as vault:purge. Run it daily.',
    target: 'config',
    flags: {},
    async run({ iam }) {
      return (await iam()).vault.purgeDeleted();
    },
  }),
];
