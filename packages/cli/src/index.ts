#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { IamError } from '@better-iam/core';
import { builtinCommands } from './commands/index.js';
import { CliError, errorCode, usageCodes } from './errors.js';
import {
  createCliProgram,
  manifestOf,
  type Cli,
  type CliIO,
  type CliManifest,
  type CreateCliOptions,
} from './framework.js';

export { builtinCommands } from './commands/index.js';
export { CliError, usageError } from './errors.js';
export {
  commandHelp,
  defineCommand,
  type ArgSpec,
  type Cli,
  type CliIO,
  type CliManifest,
  type CommandContext,
  type CommandSpec,
  type CommandTarget,
  type CommonFlags,
  type CreateCliOptions,
  type FlagSpec,
  type FlagSpecs,
  type FlagValues,
} from './framework.js';
export {
  configFileNames,
  configFromEnv,
  findConfigFile,
  loadConfig,
  type CliSettings,
  type ConfigContext,
  type ConfigExport,
  type ConfigModule,
} from './config.js';
export {
  createProfileStore,
  credentialsPath,
  type ProfileStore,
  type ProfileSummary,
  type StoredProfile,
} from './profiles.js';
export { listRoutes, localTransport, remoteTransport, type ApiTransport } from './transport.js';
export { formatResult, selectPath, type OutputFormat } from './output.js';
export {
  lintTenantConfig,
  loadTenantConfig,
  type TenantConfigContext,
  type TenantConfigLint,
} from './tenant-config.js';

const version: string = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
).version;

function hiddenPrompt(question: string): Promise<string> {
  return new Promise((resolvePrompt, reject) => {
    const input = process.stdin;
    process.stderr.write(question);
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    let value = '';
    const cleanup = () => {
      input.off('data', onData);
      input.setRawMode(false);
      input.pause();
      process.stderr.write('\n');
    };
    const onData = (chunk: string) => {
      for (const character of chunk) {
        const code = character.charCodeAt(0);
        // Enter or end-of-transmission finishes; Ctrl+C cancels; Backspace/Delete edits.
        if (code === 13 || code === 10 || code === 4) {
          cleanup();
          resolvePrompt(value);
          return;
        }
        if (code === 3) {
          cleanup();
          reject(new CliError('CANCELLED', 'Cancelled'));
          return;
        }
        if (code === 127 || code === 8) value = value.slice(0, -1);
        else if (code >= 32) value += character;
      }
    };
    input.on('data', onData);
  });
}

async function visiblePrompt(question: string): Promise<string> {
  const { createInterface } = await import('node:readline/promises');
  const reader = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await reader.question(question);
  } finally {
    reader.close();
  }
}

/** The process's own IO: stdout, stderr, `process.env`, and prompts when both stdin and stderr are terminals. */
export function processIO(): CliIO {
  const interactive = Boolean(process.stdin.isTTY && process.stderr.isTTY);
  return {
    out: (message) => console.log(message),
    err: (message) => console.error(message),
    env: process.env,
    cwd: process.cwd(),
    ...(interactive
      ? {
          prompt: (question: string, options?: { hidden?: boolean }) =>
            options?.hidden ? hiddenPrompt(question) : visiblePrompt(question),
        }
      : {}),
    async stdin() {
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk as Buffer));
      return Buffer.concat(chunks).toString('utf8');
    },
  };
}

const program = createCliProgram(builtinCommands, version, processIO);

/**
 * Creates a `better-iam`-style program from code: the built-in commands plus your own (`defineCommand`), with the same
 * parsing, help, configuration loading, and output. Use it to ship a project CLI, or to run commands in tests.
 */
export function createCli(options?: CreateCliOptions): Cli {
  return program(options);
}

const defaultCli = program();

/**
 * Runs one `better-iam` command line (without the program name) and resolves when it finishes; failures reject with an
 * `IamError` (or `CliError`) whose `code` says what went wrong. This command loads trusted application configuration
 * as executable JavaScript.
 */
export async function runCli(argv: string[], io?: CliIO): Promise<void> {
  return defaultCli.run(argv, io);
}

/** The machine-readable description of every built-in command (what `better-iam help --json` prints), for docs and tools. */
export function cliManifest(): CliManifest {
  return manifestOf(builtinCommands, version);
}

/**
 * Runs the CLI like the `better-iam` binary: prints `CODE: message` (and a hint) on failure and resolves with the exit
 * status, 0 on success, 2 for a usage mistake, 1 otherwise. For wrappers that ship their own binary.
 */
export async function main(
  argv: string[] = process.argv.slice(2),
  cli: Cli = defaultCli,
): Promise<number> {
  try {
    await cli.run(argv);
    return 0;
  } catch (error) {
    const code = errorCode(error);
    // Messages can come from a remote server: control characters (terminal escapes) are dropped before printing.
    const printable = (text: string) => text.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ');
    const message = printable(error instanceof Error ? error.message : String(error));
    // IAM errors (local or remote) and Node system errors (ENOENT, EEXIST) say what went wrong; anything else may
    // carry driver details such as connection strings, so it stays generic unless BETTER_IAM_DEBUG is set.
    const known =
      code !== undefined &&
      (error instanceof IamError ||
        (error as Error).name === 'IamClientError' ||
        /^(E[A-Z]+|ERR_[A-Z_]+)$/.test(code));
    if (known) console.error(`${printable(code)}: ${message}`);
    else
      console.error(
        'Better IAM command failed. Check configuration and database connectivity (set BETTER_IAM_DEBUG=1 for details).',
      );
    if (error instanceof CliError && error.hint) console.error(`Hint: ${error.hint}`);
    if (process.env.BETTER_IAM_DEBUG && error instanceof Error && error.stack)
      console.error(error.stack);
    return code !== undefined && usageCodes.has(code) ? 2 : 1;
  }
}

/**
 * What the `better-iam` binary does: runs `main()` on the process arguments, sets the exit status, and fails a command
 * that can never finish instead of exiting 0. For packages that ship the CLI under their own `bin`.
 */
export function runBinary(argv: string[] = process.argv.slice(2), cli: Cli = defaultCli): void {
  let settled = false;
  // If nothing is left to run while the command is still pending, it can never finish (for
  // example a lock that waits on itself); fail instead of exiting 0 without output.
  process.once('beforeExit', () => {
    if (settled) return;
    console.error('INCOMPLETE: the command stopped before it finished; nothing was reported.');
    process.exitCode = 1;
  });
  main(argv, cli)
    .then((status) => {
      process.exitCode = status;
    })
    .finally(() => {
      settled = true;
    });
}

if (
  process.argv[1] &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))
)
  runBinary();
